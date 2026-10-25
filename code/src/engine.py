"""Case engine: build/observations.csv + dataset CSVs -> output.csv.

For each request:
  1. Classify deletion vs non-deletion (rules + CLASSIFY_REQUEST events, LLM for
     texts the rules can't decide). Non-deletion -> NOT_APPLICABLE, [].
  2. Resolve the subject's user_id at requested_at (current or historical email).
  3. Gather the subject's resources. Ownership comes from, in order of trust:
       identifiers on observations (email, hash, phone, user_N), any capture time
       LINK_RESOURCE_IDENTITY events not contradicted by their own evidence file
       elimination inside a deletion-worker batch, then inside a single file
       (pairing by numeric order when several candidates remain - heuristic).
     A resource is in scope only if something at or before audit_at shows it existed.
  4. State at audit_at = latest observation with observed_at <= audit_at in a file
     captured <= audit_at (that file is the citation).
  5. Apply policy per category, emit findings / remediation / verification.
  6. Sort steps by phase, operation order, system_id, resource_id.

Usage (from the repo root):
  python code/src/engine.py --dataset dataset --build build --requests sample_deletion_requests.csv --out build/sample_pred.csv
  python code/src/engine.py --dataset dataset --build build --out output.csv
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from identity import IdentityIndex  # noqa: E402
import llm_client  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# ----------------------------------------------------------------------------- config
CONFIG = {
    # A link event whose own screenshot shows a different/unknown person is ignored.
    "trust_contradicted_links": False,
    # When k scrubbed records remain for k users, pair them by numeric order
    # (fits 3/3 sample pairs; heuristic). False -> leave them unattributed.
    "pair_by_numeric_order": True,
    # Equal observation times: does a 'present' observation beat an 'absent' one?
    "present_wins_ties": True,
    # Sort resource_id as plain strings (README) or by numeric suffix.
    "numeric_resource_sort": False,
    # Gap that splits deletion-worker events into separate batches.
    "batch_gap_minutes": 10,
}

OP_ORDER = [
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
]
OP_PHASE = {op: ("FINDING" if op.startswith("REPORT") else
                 "VERIFICATION" if op.startswith("VERIFY") else "REMEDIATION") for op in OP_ORDER}
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED", "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

# Policy keys: DELETE, REDACT, ANONYMIZE, RETAIN_AUDIT, RETAIN_HOLD, BACKUP, FLOW, ATTACHMENT, SUPPORT
PREFIX_POLICY = {
    "account": "DELETE", "profile": "DELETE", "search": "DELETE", "cache": "DELETE",
    "export": "DELETE", "marketing": "DELETE", "identifier": "DELETE", "secondary": "DELETE",
    "object": "ATTACHMENT", "support": "SUPPORT", "email_delivery": "REDACT", "tombstone": "REDACT",
    "analytics": "ANONYMIZE", "telemetry": "ANONYMIZE", "audit_record": "RETAIN_AUDIT",
    "legal_hold": "RETAIN_HOLD", "backup": "BACKUP", "data_flow": "FLOW", "connector": "FLOW",
}
# Category text in evidence overrides the prefix (longest keyword first).
CATEGORY_POLICY = [
    ("support attachment", "ATTACHMENT"), ("attachment", "ATTACHMENT"),
    ("support message", "SUPPORT"), ("email delivery", "REDACT"), ("delivery log", "REDACT"),
    ("account tombstone", "REDACT"), ("tombstone", "REDACT"), ("analytics", "ANONYMIZE"),
    ("telemetry", "ANONYMIZE"), ("security audit", "RETAIN_AUDIT"), ("legal hold", "RETAIN_HOLD"),
    ("backup", "BACKUP"), ("archive", "BACKUP"), ("data flow", "FLOW"), ("connector", "FLOW"),
    ("secondary identifier", "DELETE"), ("user profile", "DELETE"), ("search index", "DELETE"),
    ("cache", "DELETE"), ("user export", "DELETE"), ("export", "DELETE"),
    ("marketing", "DELETE"),
]
# Rule keywords expected in deletion_rules.csv for each policy (checked at start-up).
POLICY_RULE_KEYWORDS = {
    "DELETE": ["profile", "search", "cache", "export", "marketing", "secondary"],
    "REDACT": ["delivery", "tombstone"], "SUPPORT": ["support message"],
    "ATTACHMENT": ["attachment"], "ANONYMIZE": ["analytics", "telemetry"],
    "RETAIN_AUDIT": ["security audit"], "RETAIN_HOLD": ["legal hold"], "BACKUP": ["backup"],
}
SYSTEM_FALLBACK = {
    "account": "account_service", "search": "search_service", "analytics": "analytics_platform",
    "support": "support_platform", "object": "support_platform", "audit_record": "security_service",
    "data_flow": "integration_service", "connector": "integration_service",
    "backup": "backup_service", "export": "export_service", "tombstone": "identity_service",
}
DELETION_EVENT_TYPES = {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW",
                        "BLOCK_RESTORE", "PURGE_RECORD", "DELETE_ACCOUNT"}

# ----------------------------------------------------------------------------- request classification
DELETE_WORDS = [
    "delete", "erase", "remove my", "remove all", "close my account", "forget me", "be forgotten",
    "wipe", "deactivate and delete", "eliminar", "borrar", "suprimir", "cerrar mi cuenta",
    "excluir", "apagar", "encerrar minha conta", "supprimer", "effacer", "fermer mon compte",
    "削除", "消去", "退会", "삭제", "탈퇴", "지워",
]
KEEP_PHRASES = [
    "keep the account", "keep my account", "do not close", "don't close", "not close",
    "still use", "still need the account", "still need my account", "still want",
    "continue using", "without removing", "leave my profile", "leave the account",
    "information request", "portable format", "marketing lists only", "stop the promotional",
    "change the email", "replace it with", "is misspelled", "resetting the login",
    "copy of the information", "copy of last year", "what personal information",
    "mantener la cuenta", "mantener mi cuenta", "no cierren", "sigo usando",
    "manter a conta", "manter minha conta", "não encerrem", "continuo usando",
    "garder mon compte", "ne fermez pas", "j'utilise encore",
    "アカウントは残", "解約しない", "계정은 유지", "계속 사용",
]


def rule_classify(text: str) -> str:
    t = (text or "").lower()
    keep = any(p in t for p in KEEP_PHRASES)
    delete = any(w in t for w in DELETE_WORDS)
    if keep:
        return "non_deletion"
    if delete:
        return "deletion"
    return "uncertain"


def llm_classify(texts: list[str], run_id: str) -> dict[str, bool]:
    """Batch-classify unique texts with the configured free LLM. {} if unavailable."""
    if not texts or not llm_client.available():
        return {}
    system = (ROOT / "prompts" / "classify_request.md").read_text(encoding="utf-8")
    out: dict[str, bool] = {}
    for start in range(0, len(texts), 25):
        chunk = texts[start:start + 25]
        payload = json.dumps([{"i": i, "text": t} for i, t in enumerate(chunk)], ensure_ascii=False)
        key = "classify_v1_" + hashlib.sha256(payload.encode()).hexdigest()
        try:
            text = llm_client.call(purpose="classify_request", ref=f"batch_{start // 25}",
                                   system=system, text=payload, cache_key=key,
                                   max_tokens=1500, run_id=run_id)
            for r in llm_client.parse_json(text).get("results", []):
                if 0 <= int(r["i"]) < len(chunk):
                    out[chunk[int(r["i"])]] = bool(r["deletion"])
        except Exception as exc:
            print(f"[warn] classify batch {start // 25} failed: {exc}", file=sys.stderr)
    return out


# ----------------------------------------------------------------------------- helpers
def read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def iso(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_dt(s: str) -> datetime:
    return datetime.fromisoformat(iso(s).replace("Z", "+00:00"))


def num(s: str) -> int:
    m = re.search(r"(\d+)$", s or "")
    return int(m.group(1)) if m else 0


def prefix_of(rid: str) -> str:
    m = re.fullmatch(r"([a-z][a-z_]*?)_\d+", rid or "")
    return m.group(1) if m else ""


def case_key(cid: str) -> tuple:
    return (num(cid), cid)


def jl(v):
    return json.loads(v) if isinstance(v, str) and v.startswith("[") else (v or [])


# ----------------------------------------------------------------------------- world model
class World:
    def __init__(self, dataset: Path, build: Path):
        self.dataset = dataset
        self.identity = IdentityIndex(dataset)
        self.obs = read_csv(build / "observations.csv")
        for o in self.obs:
            for k in ("user_ids", "emails", "unmatched_emails", "pii_fields", "null_pii_fields",
                      "reference_fields", "match_routes", "lookup_user_ids", "ref_resource_ids"):
                o[k] = jl(o.get(k))
            o["exists"] = str(o["exists"]) == "1"
            o["is_state"] = str(o.get("is_state", "1")) != "0"
        self.links = read_csv(build / "links.csv") if (build / "links.csv").exists() else []
        for l in self.links:
            l["user_ids"] = jl(l["user_ids"])
        self.activity = sorted(read_csv(dataset / "system_activity.csv"), key=lambda r: r["event_time"])
        self.rules = read_csv(dataset / "deletion_rules.csv") if (dataset / "deletion_rules.csv").exists() else []
        self.prefix_system = self._learn_prefix_system()
        self.retention_days = self._retention_days()
        self.notes: list[str] = []

        # Visual observations without a resource id inherit it from their file's link.
        links_by_file = defaultdict(list)
        for l in self.links:
            if l.get("file_id") and l.get("resource_id"):
                links_by_file[l["file_id"]].append(l)
        for o in self.obs:
            if not o["resource_id"] and len(links_by_file.get(o["file_id"], [])) == 1:
                l = links_by_file[o["file_id"]][0]
                o["resource_id"], o["prefix"] = l["resource_id"], prefix_of(l["resource_id"])
                o["system_id"] = o["system_id"] or l.get("system_id", "")
        for o in self.obs:
            if o["resource_id"] and not o["system_id"]:
                o["system_id"] = self.system_for(o["resource_id"])

        self.obs_by_res = defaultdict(list)
        for o in self.obs:
            if o["resource_id"]:
                self.obs_by_res[o["resource_id"]].append(o)
        self.events_by_res = defaultdict(list)
        for a in self.activity:
            if a.get("resource_id"):
                self.events_by_res[a["resource_id"]].append(a)

        self.owners: dict[str, dict[str, str]] = defaultdict(dict)  # rid -> {user: route}
        self.lookup_times: dict[tuple[str, str], list[str]] = defaultdict(list)  # (rid, user) -> times
        self.referenced_by: dict[str, list[dict]] = defaultdict(list)  # target rid -> referencing obs
        self._link_direct()
        self._link_events()
        strong = {rid for rid, us in self.owners.items() if us}
        self._link_references(strong)
        self._link_lookups(strong)
        self._link_batches()
        self._link_files()
        self.by_user = defaultdict(set)
        for rid, us in self.owners.items():
            for u in us:
                self.by_user[u].add(rid)

    # ---- config learned from data ---------------------------------------------
    def _learn_prefix_system(self) -> dict:
        votes = defaultdict(Counter)
        so = self.dataset / "sample_output.csv"
        if so.exists():
            for row in read_csv(so):
                for st in json.loads(row["steps_json"] or "[]"):
                    votes[prefix_of(st["resource_id"])][st["system_id"]] += 1
        for o in self.obs:
            if o["system_id"] and o["prefix"]:
                votes[o["prefix"]][o["system_id"]] += 0.01
        return {p: c.most_common(1)[0][0] for p, c in votes.items() if p}

    def system_for(self, rid: str) -> str:
        p = prefix_of(rid)
        return self.prefix_system.get(p) or SYSTEM_FALLBACK.get(p, f"{p}_service")

    def _retention_days(self) -> int | None:
        for r in self.rules:
            text = keyword_text(" ".join(str(v) for v in r.values()))
            if "security audit" not in text:
                continue
            for k, v in r.items():
                if "retention" in k.lower() and str(v).strip().isdigit():
                    return int(v)
            m = re.search(r"(\d+)\s*(day|month|year)", text)
            if m:
                n, unit = int(m.group(1)), m.group(2)
                return n * {"day": 1, "month": 30, "year": 365}[unit]
        return None

    def check_rules(self) -> list[str]:
        text = keyword_text(" ".join(" ".join(str(v) for v in r.values()) for r in self.rules))
        missing = [f"{pol}:{kw}" for pol, kws in POLICY_RULE_KEYWORDS.items() for kw in kws
                   if kw not in text]
        return missing

    # ---- ownership ------------------------------------------------------------
    def _add_owner(self, rid: str, uid: str, route: str) -> None:
        if rid and uid and uid not in self.owners[rid]:
            self.owners[rid][uid] = route

    def _link_direct(self) -> None:
        for o in self.obs:
            for u in o["user_ids"]:
                self._add_owner(o["resource_id"], u, "identifier:" + ",".join(o["match_routes"]))

    def _link_events(self) -> None:
        file_obs = defaultdict(list)
        for o in self.obs:
            file_obs[o["file_id"]].append(o)
        for l in self.links:
            for u in l["user_ids"]:
                contradicted = False
                fo = [o for o in file_obs.get(l.get("file_id", ""), [])
                      if not o["resource_id"] or o["resource_id"] == l["resource_id"]]
                shown_users = {x for o in fo for x in o["user_ids"]}
                shown_unknown = any(o["unmatched_emails"] for o in fo)
                if fo and u not in shown_users and (shown_users or shown_unknown):
                    contradicted = True
                    self.notes.append(f"contradicted link {l['activity_id']}: {l['resource_id']} -> {u}; "
                                      f"file {l['file_id']} shows {sorted(shown_users) or 'unknown person'}")
                if contradicted and not CONFIG["trust_contradicted_links"]:
                    continue
                self._add_owner(l["resource_id"], u, f"link:{l['activity_id']}")

    def _link_references(self, strong: set[str]) -> None:
        """Route 'reference': a record names another one (source_resource_id = account_006).

        One step only, from a record with exactly one owner and that owner from a strong
        route; the target must have no strong owner. A record linked this way never
        passes ownership on, because only strong-owned records are sources.
        """
        for o in self.obs:
            src = o["resource_id"]
            for target in o["ref_resource_ids"]:
                self.referenced_by[target].append(o)
                if src not in strong or len(self.owners[src]) != 1 or target in strong:
                    continue
                self._add_owner(target, next(iter(self.owners[src])), "reference")

    def _link_lookups(self, strong: set[str]) -> None:
        """Weak route: a user whose identifier was used as the lookup key for a resource.

        Only for resources no strong route owns. A lookup can return a stale or wrong
        record, so audit_case keeps one weak resource per type (the latest lookup).
        """
        for o in self.obs:
            rid = o["resource_id"]
            if not rid or rid in strong:
                continue
            for u in o["lookup_user_ids"]:
                self._add_owner(rid, u, "lookup_key")
                if o["observed_at"]:
                    self.lookup_times[(rid, u)].append(o["observed_at"])

    def weak_pick(self, uid: str, rids: list[str], at: str) -> set[str]:
        """Of the weakly owned rids, keep per prefix the one with the latest lookup <= at."""
        best: dict[str, tuple[str, str]] = {}
        for rid in rids:
            times = [t for t in self.lookup_times.get((rid, uid), []) if t <= at]
            if not times:
                continue
            p = prefix_of(rid)
            if p not in best or max(times) > best[p][0]:
                best[p] = (max(times), rid)
        return {rid for _, rid in best.values()}

    def _batches(self) -> list[list[dict]]:
        ev = [a for a in self.activity if a["event_type"] in DELETION_EVENT_TYPES and a.get("resource_id")]
        batches, cur = [], []
        gap = timedelta(minutes=CONFIG["batch_gap_minutes"])
        for a in ev:
            if cur and (to_dt(a["event_time"]) - to_dt(cur[-1]["event_time"]) > gap
                        or a.get("source_system") != cur[-1].get("source_system")):
                batches.append(cur)
                cur = []
            cur.append(a)
        if cur:
            batches.append(cur)
        return batches

    def _eliminate(self, group_rids: set[str], users: set[str], label: str) -> None:
        """Assign unowned resources in a group to the group's users who lack that type."""
        unowned = defaultdict(list)
        for rid in group_rids:
            if not self.owners.get(rid) and prefix_of(rid) not in ("account",):
                unowned[prefix_of(rid)].append(rid)
        if not users:
            return
        held = defaultdict(set)
        for rid, us in self.owners.items():
            for u in us:
                held[u].add(prefix_of(rid))
        for p, cands in unowned.items():
            lacking = sorted((u for u in users if p not in held[u]), key=num)
            cands = sorted(set(cands), key=num)
            if not lacking or len(cands) != len(lacking):
                continue
            if len(cands) > 1 and not CONFIG["pair_by_numeric_order"]:
                continue
            route = f"{label}_single" if len(cands) == 1 else f"{label}_numeric_order_heuristic"
            for rid, u in zip(cands, lacking):
                self._add_owner(rid, u, route)

    def _link_batches(self) -> None:
        for b in self._batches():
            rids = {a["resource_id"] for a in b}
            # Batch users = owners of the accounts deleted in it. Accounts with no known
            # owner add no user, so _eliminate's count check may then pair wrongly.
            users = {u for rid in rids if prefix_of(rid) == "account" for u in self.owners.get(rid, {})}
            self._eliminate(rids, users, "batch")

    def _link_files(self) -> None:
        by_file = defaultdict(set)
        for o in self.obs:
            if o["resource_id"]:
                by_file[o["file_id"]].add(o["resource_id"])
        for fid, rids in by_file.items():
            users = {u for rid in rids for u in self.owners.get(rid, {})}
            if len(users) <= 3:  # only small, case-focused files
                self._eliminate(rids, users, "file")

    # ---- state ----------------------------------------------------------------
    # Request lines (is_state False) link owners but never prove existence or state.
    def existed_by(self, rid: str, at: str) -> bool:
        if any(o["is_state"] and o["observed_at"] and o["observed_at"] <= at
               for o in self.obs_by_res.get(rid, [])):
            return True
        return any(iso(a["event_time"]) <= at for a in self.events_by_res.get(rid, []))

    def absence_grounds(self, rid: str, at: str) -> str:
        """Why a never-observed resource may be taken as deleted: '' if no grounds."""
        for a in self.events_by_res.get(rid, []):
            if (a["event_type"] == "DELETE_RECORD" and a.get("reported_result") == "SUCCESS"
                    and iso(a["event_time"]) <= at):
                return f"deletion_reported:{a['activity_id']}"
        for o in self.referenced_by.get(rid, []):
            if o["observed_at"] and o["observed_at"] <= at:
                return f"referenced_by:{o['resource_id']}"
        return ""

    def state_at(self, rid: str, at: str) -> dict | None:
        cands = [o for o in self.obs_by_res.get(rid, [])
                 if o["is_state"] and o["observed_at"] and o["observed_at"] <= at
                 and o["file_captured_at"] <= at]
        if not cands:
            return None
        pw = CONFIG["present_wins_ties"]
        return max(cands, key=lambda o: (o["observed_at"], (o["exists"] if pw else not o["exists"]),
                                         o["file_captured_at"], num(o["file_id"])))


# ----------------------------------------------------------------------------- policy
def keyword_text(s: str) -> str:
    """Lower-case and turn SUPPORT_MESSAGE-style names into 'support message' for keyword search."""
    return s.lower().replace("_", " ")


ATTACHMENT_MARKER_RE = re.compile(
    r"attachment|\bfile(?:_name)?\\?[\"']?\s*[:=]\s*\\?[\"']?[\w\-]+\.[a-z0-9]{2,4}\b", re.I)
MESSAGE_MARKER_RE = re.compile(r"message_(?:text|excerpt|body|pii_scan)", re.I)


def support_kind(rid: str, world: World) -> tuple[str, str]:
    """('attachment' | 'message' | '', why) for a support record without a category.

    Markers on the record itself first (file=..., ticket_attachments, attachment_pii_scan;
    message_text, message_pii_scan). Failing that, the operation the deletion workflow
    ran on it: a workflow deletes attachments and redacts messages (heuristic; fits all
    9 sample support records with events).
    """
    att = msg = False
    for o in world.obs_by_res.get(rid, []):
        raw = o.get("raw", "")
        att |= bool(ATTACHMENT_MARKER_RE.search(raw))
        msg |= bool(MESSAGE_MARKER_RE.search(raw))
    if att != msg:
        return ("attachment" if att else "message"), "record_marker"
    ops = {a["event_type"] for a in world.events_by_res.get(rid, [])}
    if ("DELETE_RECORD" in ops) != ("REDACT_RECORD" in ops):
        return ("attachment" if "DELETE_RECORD" in ops else "message"), "workflow_operation_heuristic"
    return "", ""


def policy_for(rid: str, obs: dict | None, world: World) -> str:
    texts = keyword_text(" ".join(filter(None, [
        *(o.get("category", "") for o in world.obs_by_res.get(rid, [])),
        *(o.get("section", "") for o in world.obs_by_res.get(rid, [])),
    ])))
    for kw, pol in CATEGORY_POLICY:
        if kw in texts:
            return pol
    pol = PREFIX_POLICY.get(prefix_of(rid), "DELETE")
    if pol == "SUPPORT":
        kind, _ = support_kind(rid, world)
        pol = {"attachment": "ATTACHMENT", "message": "MESSAGE"}.get(kind, pol)
    return pol


def legal_hold_active(obs: dict, at: str) -> bool:
    raw = obs.get("raw", "").lower()
    if re.search(r"(released|lifted|expired|inactive|closed)", raw) and "active\": true" not in raw:
        m = re.search(r"released_at\"?[:=]\s*\"?(\d{4}-\d{2}-\d{2}[t ][\d:]+z?)", raw)
        return bool(m and iso(m.group(1)) > at)
    return True


def audit_expired(obs: dict, at: str, days: int | None) -> bool:
    if not days:
        return False
    m = re.search(r"(?:event_time|created_at|logged_at|recorded_at)\"?[:=]\s*\"?(\d{4}-\d{2}-\d{2}[T ][\d:]+Z?)",
                  obs.get("raw", ""))
    return bool(m and to_dt(at) - to_dt(m.group(1)) > timedelta(days=days))


def plan_resource(rid: str, obs: dict, uid: str, world: World, at: str) -> tuple[list[str], str]:
    """Operations for one resource given its state at audit_at. Returns (ops, policy)."""
    pol = policy_for(rid, obs, world)
    st, exists = obs["state"], obs["exists"]
    has_pii = st in ("FOUND", "IDENTIFIABLE")
    owners = set(world.owners.get(rid, {}))

    if pol == "SUPPORT":
        # Handover vocabulary encodes treatment: FOUND = delete-type, IDENTIFIABLE = redact-type.
        pol = "DELETE" if (st == "FOUND" and obs["source_type"] == "text" and len(owners) <= 1) else "REDACT"
    if pol == "ATTACHMENT":
        pol = "DELETE" if owners <= {uid} else "REDACT"
    if pol == "MESSAGE":
        pol = "REDACT"
    if pol == "RETAIN_HOLD" and not legal_hold_active(obs, at):
        pol = "DELETE"
    if pol == "RETAIN_AUDIT" and audit_expired(obs, at, world.retention_days):
        pol = "DELETE"

    if not exists and pol not in ("RETAIN_AUDIT", "RETAIN_HOLD"):
        return ["VERIFY_RECORD_ABSENT"], pol
    if pol == "DELETE":
        return ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"], pol
    if pol == "REDACT":
        if has_pii:
            return ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"], pol
        return ["VERIFY_RECORD_REDACTED"], pol
    if pol == "ANONYMIZE":
        if has_pii or st == "REDACTED":  # a kept user reference still links it
            return ["REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"], pol
        return ["VERIFY_RECORD_ANONYMIZED"], pol
    if pol in ("RETAIN_AUDIT", "RETAIN_HOLD"):
        if not exists:
            world.notes.append(f"retained record {rid} missing at {at}")
            return [], pol
        return ["VERIFY_RECORD_PRESENT"], pol
    if pol == "FLOW":
        if st == "ACTIVE":
            return ["REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"], pol
        return ["VERIFY_DATA_FLOW_DISABLED"], pol
    if pol == "BACKUP":
        if st == "ACTIVE":
            return ["REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"], pol
        return ["VERIFY_RESTORE_BLOCKED"], pol
    return ["VERIFY_RECORD_ABSENT"], pol


def sort_key(step: dict):
    rid = step["resource_id"]
    r = (prefix_of(rid), num(rid)) if CONFIG["numeric_resource_sort"] else rid
    return (PHASE_ORDER[step["phase"]], OP_ORDER.index(step["operation"]), step["system_id"], r)


# ----------------------------------------------------------------------------- per case
def audit_case(req: dict, world: World, label: str, classify_events: dict) -> tuple[str, list, dict]:
    at = iso(req["audit_at"])
    debug = {"case_id": req["case_id"], "audit_at": at, "classification": label}
    uid = world.identity.resolve_email(req["email"], iso(req["requested_at"]))
    debug["user_id"] = uid
    if uid and uid in classify_events:
        debug["classify_event"] = classify_events[uid]
    if label == "non_deletion":
        return "NOT_APPLICABLE", [], debug
    if not uid:
        debug["error"] = "email resolves to no user"
        return "COMPLETE", [], debug

    resources, skipped = [], []
    owned = sorted(world.by_user.get(uid, set()))
    weak = [rid for rid in owned if world.owners[rid][uid] == "lookup_key"]
    keep_weak = world.weak_pick(uid, weak, at)
    unobserved = []  # linked to the subject, never observed by audit_at, deletion-type policy
    for rid in owned:
        if rid in weak and rid not in keep_weak:
            skipped.append({"resource_id": rid, "reason": "weak lookup link superseded or after audit_at"})
            continue
        obs = world.state_at(rid, at)
        if obs is None:
            grounds = world.absence_grounds(rid, at)
            if policy_for(rid, None, world) == "DELETE" and grounds:
                unobserved.append({"resource_id": rid, "system_id": world.system_for(rid),
                                   "state": "UNOBSERVED", "policy": "DELETE",
                                   "ops": ["VERIFY_RECORD_ABSENT"], "evidence": "", "obs_id": "",
                                   "owner_route": world.owners[rid][uid], "absence_grounds": grounds})
                continue
            reason = ("no existence evidence by audit_at" if not world.existed_by(rid, at)
                      else "no citable observation by audit_at")
            skipped.append({"resource_id": rid, "reason": reason})
            continue
        ops, pol = plan_resource(rid, obs, uid, world, at)
        resources.append({"resource_id": rid, "system_id": obs["system_id"] or world.system_for(rid),
                          "state": obs["state"], "policy": pol, "ops": ops,
                          "evidence": obs["file_id"], "obs_id": obs["obs_id"],
                          "owner_route": world.owners[rid][uid],
                          **({"support_kind": "/".join(support_kind(rid, world))}
                             if prefix_of(rid) == "support" else {})})
    incomplete = any(OP_PHASE[op] == "FINDING" for r in resources for op in r["ops"])
    # Never-observed, deletion-type resources: an INCOMPLETE case's verification steps
    # carry no citation, so absence can be a post-remediation check. A COMPLETE case
    # needs a citation; samples cite a snapshot missing the record, never a deletion
    # event, so those are left out until snapshot absence is modelled.
    if incomplete:
        resources += unobserved
    else:
        skipped += [{"resource_id": r["resource_id"], "reason": "unobserved; COMPLETE case needs a citation"}
                    for r in unobserved]
    debug["unobserved_absent"] = {"added": len(unobserved) if incomplete else 0,
                                  "withheld_complete": 0 if incomplete else len(unobserved)}
    debug["resources"], debug["skipped"] = resources, skipped

    steps = []
    for r in resources:
        for op in r["ops"]:
            phase = OP_PHASE[op]
            if not incomplete and phase != "VERIFICATION":
                continue
            ev = r["evidence"] if (phase == "FINDING" or (phase == "VERIFICATION" and not incomplete)) else ""
            steps.append({"phase": phase, "system_id": r["system_id"], "resource_id": r["resource_id"],
                          "operation": op, "state": OP_STATE[op], "evidence_id": ev})
    steps.sort(key=sort_key)
    for i, s in enumerate(steps, 1):
        s["step_no"] = i
    steps = [{k: s[k] for k in ("step_no", "phase", "system_id", "resource_id", "operation",
                                "state", "evidence_id")} for s in steps]
    return ("INCOMPLETE" if incomplete else "COMPLETE"), steps, debug


def classify_all(requests: list[dict], world: World, run_id: str, use_llm: bool) -> tuple[dict, dict]:
    # CLASSIFY_REQUEST events -> subject user via the account they name
    classify_events = {}
    for a in world.activity:
        if a["event_type"] == "CLASSIFY_REQUEST" and "non-deletion" in a.get("details", "").lower():
            for u in world.owners.get(a["resource_id"], {}):
                classify_events[u] = a["activity_id"]
    rule = {r["case_id"]: rule_classify(r["request_text"]) for r in requests}
    llm = {}
    if use_llm:
        llm = llm_classify(sorted({r["request_text"] for r in requests}), run_id)
    labels, report = {}, []
    for r in requests:
        cid, rl = r["case_id"], rule[r["case_id"]]
        lm = llm.get(r["request_text"])
        uid = world.identity.resolve_email(r["email"], iso(r["requested_at"]))
        ev = uid in classify_events if uid else False
        if rl == "non_deletion" or ev:
            lab = "non_deletion"
        elif rl == "deletion":
            lab = "deletion"
        else:
            lab = "non_deletion" if lm is False else "deletion"
        labels[cid] = lab
        if (lm is not None and (lm is False) != (lab == "non_deletion")) or (ev and rl != "non_deletion"):
            report.append({"case_id": cid, "rule": rl, "llm_deletion": lm, "classify_event": ev,
                           "final": lab, "text": r["request_text"][:120]})
    return labels, {"disagreements": report, "classify_events": classify_events}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--build", default="build")
    ap.add_argument("--requests", default="deletion_requests.csv")
    ap.add_argument("--out", default="output.csv")
    ap.add_argument("--no-llm", action="store_true", help="skip LLM request classification")
    ap.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ"))
    a = ap.parse_args()

    dataset, build = Path(a.dataset), Path(a.build)
    world = World(dataset, build)
    missing = world.check_rules()
    if missing:
        print(f"[warn] policy keywords not found in deletion_rules.csv: {missing}", file=sys.stderr)
    req_path = Path(a.requests) if Path(a.requests).exists() else dataset / a.requests
    requests = sorted(read_csv(req_path), key=lambda r: case_key(r["case_id"]))
    labels, cls_report = classify_all(requests, world, a.run_id, not a.no_llm)

    rows, debug = [], []
    for r in requests:
        status, steps, dbg = audit_case(r, world, labels[r["case_id"]], cls_report["classify_events"])
        rows.append({"case_id": r["case_id"], "deletion_status": status,
                     "steps_json": json.dumps(steps, separators=(",", ":"))})
        debug.append(dbg)

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        w.writeheader()
        w.writerows(rows)
    dbg_path = build / f"{out.stem}_debug.jsonl"
    with open(dbg_path, "w", encoding="utf-8") as f:
        for d in debug:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    routes = Counter(r["owner_route"].split(":")[0] for d in debug for r in d.get("resources", []))
    summary = {
        "cases": len(rows), "status": dict(Counter(r["deletion_status"] for r in rows)),
        "classification_disagreements": cls_report["disagreements"],
        "ownership_routes_used": dict(routes),
        "skipped_resources": sum(len(d.get("skipped", [])) for d in debug),
        "unobserved_absent_added": sum(d.get("unobserved_absent", {}).get("added", 0) for d in debug),
        "unobserved_absent_withheld_complete": sum(d.get("unobserved_absent", {}).get("withheld_complete", 0)
                                                   for d in debug),
        "unresolved_emails": [d["case_id"] for d in debug if d.get("error")],
        "notes": world.notes[:50],
    }
    (build / f"{out.stem}_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False),
                                                     encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "notes"}, indent=2, ensure_ascii=False))
    if world.notes:
        print(f"{len(world.notes)} notes -> {build / (out.stem + '_summary.json')}")


if __name__ == "__main__":
    main()

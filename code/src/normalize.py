"""Normalize every evidence file into one observation table.

One row = "file F says resource R in system S was in state X at time T, and
these identifiers / users appear on it". Downstream code (state replay, policy,
step generation) works only on this table plus the CSVs, never on raw files.

Supported evidence:
  * pipe-delimited handover text  time | system | resource | category | state | identifier
  * SQLite-compatible SQL dumps    (header 'Captured at:', optional snapshot_scope table)
  * JSON exports / snapshot bundles (sections with their own capture times)
  * key=value readback logs        (lookup_key, enabled=, restore_allowed=, HTTP status)
  * PDFs                           (text layer first, vision model if no usable text)
  * PNG/JPG screenshots            (vision model, cached by file hash)

The normalizer records facts only. It does not apply deletion rules, decide
which observation wins, or drop files captured after a case's audit_at; those
are per-case decisions made later. It also extracts LINK_RESOURCE_IDENTITY
events from system_activity.csv into links.csv, because they are the only way
some screenshots get a resource ID.

Usage (from the repo root):
  python code/src/normalize.py --dataset dataset --out build
  python code/src/normalize.py --dataset dataset --out build --visual-fallback manual.json
  python code/src/normalize.py --dataset dataset --out build --score-visual manual.json
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from identity import IdentityIndex, EMAIL_RE, NON_IDENTITY_KEY_PARTS  # noqa: E402
import llm_client  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PROMPT_VERSION = "vision_extract_v1"

OBS_COLUMNS = [
    "obs_id", "file_id", "source_type", "origin", "section", "file_captured_at",
    "observed_at", "time_source", "system_id", "raw_system", "resource_id", "prefix",
    "category", "state", "raw_status", "exists", "http_status", "pii_fields",
    "null_pii_fields", "reference_fields", "emails", "hashes", "phones", "user_refs",
    "user_ids", "match_routes", "unmatched_emails", "lookup_values", "lookup_user_ids",
    "ref_resource_ids", "is_state", "raw",
]

CANONICAL_STATES = {"NOT_FOUND", "FOUND", "IDENTIFIABLE", "ANONYMIZED", "REDACTED",
                    "ACTIVE", "DISABLED", "BLOCKED"}
ABSENT_WORDS = {"NOT_FOUND", "ABSENT", "DELETED", "PURGED", "MISSING", "REMOVED", "GONE", "NOT FOUND"}
FLOW_PREFIXES = {"data_flow", "connector"}
BACKUP_PREFIXES = {"backup"}

TIME_KEYS = ("observed_at", "checked_at", "section_captured_at", "captured_at", "snapshot_at",
             "snapshot_time", "as_of", "scope_time", "exported_at", "generated_at", "read_at")
SYSTEM_KEYS = ("system_id", "system", "service", "source_system", "target_system", "platform")
CATEGORY_KEYS = ("category", "data_category", "record_category", "record_type")
STATE_KEYS = ("state", "status", "record_state", "record_status", "lookup_result", "result")
ID_KEYS = ("resource_id", "resource", "id", "record_id", "object_id")
ENABLED_KEYS = ("enabled", "is_enabled", "active_flow", "sync_enabled", "connector_enabled")
RESTORE_KEYS = ("restore_allowed", "restorable", "can_restore", "restore_enabled")
# restore_candidate_evaluated: eligible=true deletion_block=false -> still restorable.
RESTORE_ELIGIBLE_KEYS = ("eligible", "restore_eligible")
RESTORE_BLOCK_KEYS = ("deletion_block", "restore_block", "restore_blocked")
# restore_authorization_completed: decision=deny|allow.
RESTORE_DECISION_KEYS = ("decision", "restore_decision")
DENY_WORDS = {"deny", "denied", "reject", "rejected", "block", "blocked"}
ALLOW_WORDS = {"allow", "allowed", "approve", "approved", "grant", "granted", "permit", "permitted"}
DIRECT_PII_PARTS = ("email", "phone", "mobile", "name", "hash", "address", "birth")
NOT_PII_NAMES = {"system_name", "table_name", "file_name", "filename", "hostname", "host_name",
                 "service_name", "job_name", "connector_name", "category_name", "snapshot_name",
                 "source_name", "flow_name", "bucket_name", "object_name", "field_name",
                 "lookup_key_name", "hash_algorithm", "integrity_seal", "seal",
                 # the query used to look a record up is not content of the record
                 "lookup_key", "lookup", "query", "search_key", "_line", "_table", "listed_under"}
REFERENCE_PARTS = ("reference", "user_id", "subject", "customer_id")

TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?"
)
JSON_KV_RE = re.compile(r'"(\w[\w.\-]*)"\s*:\s*("(?:[^"\\]|\\.)*"|-?[\w.]+)')
KV_RE = re.compile(r'(\w[\w.\-]*)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;|]+)')
HTTP_RE = re.compile(r"\b(?:HTTP\S*\s+|(?:http_status|status_code|status|code)[\"']?\s*[=:]\s*[\"']?)(\d{3})\b",
                     re.I)
HTTP_KEYS = {"status_code", "http_status", "code"}
BARE_HTTP_RE = re.compile(r"(?<![\w.:\-])(200|204|404|410)(?![\w.:\-])")
# A log line announcing a request (profile_lookup_started, index_query_started, ...)
# says what was asked, not what the record looked like.
REQUEST_EVENT_RE = re.compile(r"\b[a-z]+(?:_[a-z]+)*_started\b")
# The keys a lookup or scan was made with. They say what the caller asked for, and
# can be stale, so identifiers in them are kept apart as a weak ownership route -
# even subject_ref, which names a user_N directly.
LOOKUP_KEY_NAMES = {"lookup_key", "search_key", "subject_ref", "subject_key", "match_key",
                    "owner_key", "scan_key"}
LOOKUP_VALUE_RE = re.compile(
    r"\b(?:" + "|".join(sorted(LOOKUP_KEY_NAMES)) + r")\\?[\"']?\s*[:=]\s*\\?[\"']?([^\"'\\\s,;|}]+)")
TRACE_RE = re.compile(r"\b((?:tr|rb)-[0-9A-Za-z-]+)\b")


def is_reference_field(name: str) -> bool:
    """Fields that point at another record (search_001.source_resource_id = account_006)."""
    return name != "resource_id" and (name.endswith("_resource_id") or name.startswith(("source_", "parent_"))
                                      or name == "account_ref")


# --------------------------------------------------------------------------- helpers
def iso(value) -> str:
    """Normalize a timestamp to 'YYYY-MM-DDTHH:MM:SSZ' (UTC). '' if unparseable."""
    if value is None:
        return ""
    s = str(value).strip()
    m = TS_RE.search(s)
    if not m:
        return ""
    s = m.group(0).replace(" ", "T", 1).replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", s):
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def boolish(v):
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on", "enabled", "allowed", "active"):
        return True
    if s in ("0", "false", "no", "n", "off", "disabled", "blocked", "denied", "inactive"):
        return False
    return None


def is_blank(v) -> bool:
    if isinstance(v, (list, tuple, set, dict)):
        return not any(not is_blank(x) for x in v)
    return v is None or str(v).strip().lower() in ("", "null", "none", "nan", "[redacted]",
                                                   "redacted", "***", "n/a", "-")


def category_key(s) -> str:
    return re.sub(r"\s+", " ", str(s or "").lower().replace("_", " ")).strip()


def flatten(d: dict, prefix: str = "", skip_resource_children=None) -> dict:
    """Flatten nested dicts (not lists of resource records) into dotted keys."""
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            if skip_resource_children and skip_resource_children(v, k):
                continue
            out.update(flatten(v, key + ".", skip_resource_children))
        elif isinstance(v, list):
            if all(not isinstance(x, (dict, list)) for x in v):
                out[key] = v
        else:
            out[key] = v
    return out


def leaf(key: str) -> str:
    return key.rsplit(".", 1)[-1].lower()


def first(flat: dict, names) -> tuple[str, object] | tuple[None, None]:
    for k, v in flat.items():
        if leaf(k) in names and not is_blank(v):
            return k, v
    return None, None


# --------------------------------------------------------------------------- context
class Context:
    """Shared lookups: identity index, resource-id grammar, prefix -> system_id map."""

    def __init__(self, dataset: Path):
        self.dataset = dataset
        self.identity = IdentityIndex(dataset)
        self.prefix_system: dict[str, str] = {}
        self.known_systems: set[str] = set()
        prefixes = {"account", "search", "analytics", "support", "email_delivery", "cache",
                    "audit_record", "export", "data_flow", "backup", "tombstone", "legal_hold",
                    "object", "marketing", "connector", "telemetry", "profile"}
        votes: dict[str, Counter] = defaultdict(Counter)
        so = dataset / "sample_output.csv"
        if so.exists():
            for row in csv.DictReader(open(so, encoding="utf-8")):
                for st in json.loads(row["steps_json"] or "[]"):
                    p = self.prefix_of(st["resource_id"])
                    if p:
                        prefixes.add(p)
                        votes[p][st["system_id"]] += 1
                    self.known_systems.add(st["system_id"])
        sa = dataset / "system_activity.csv"
        if sa.exists():
            for row in csv.DictReader(open(sa, encoding="utf-8")):
                p = self.prefix_of(row.get("resource_id", ""))
                if p:
                    prefixes.add(p)
                    for col in ("target_system",):
                        if row.get(col) in self.known_systems:
                            votes[p][row[col]] += 0.1  # weak vote; samples dominate
        self.prefix_system = {p: c.most_common(1)[0][0] for p, c in votes.items()}
        alt = "|".join(sorted((re.escape(p) for p in prefixes), key=len, reverse=True))
        self.resource_re = re.compile(rf"(?<![A-Za-z0-9_])(?:{alt})_\d+(?![A-Za-z0-9_])")

    @staticmethod
    def prefix_of(resource_id: str) -> str:
        m = re.fullmatch(r"([a-z][a-z_]*?)_\d+", resource_id or "")
        if not m or m.group(1) in ("user", "evidence", "activity", "audit", "case", "rule"):
            return ""
        return m.group(1)

    def system_for(self, resource_id: str, raw_system: str) -> str:
        if raw_system in self.known_systems:
            return raw_system
        return self.prefix_system.get(self.prefix_of(resource_id), "")

    def resources_in(self, text: str) -> list[str]:
        return list(dict.fromkeys(self.resource_re.findall(text or "")))


# --------------------------------------------------------------------------- observation
def classify_fields(flat: dict, identity_hits: dict):
    """Split fields into direct-PII present / direct-PII null / references present."""
    pii, null_pii, refs = [], [], []
    for k, v in flat.items():
        name = leaf(k)
        if any(p in name for p in NON_IDENTITY_KEY_PARTS) or name in NOT_PII_NAMES:
            continue
        is_ref = any(p in name for p in REFERENCE_PARTS)
        is_pii_name = any(p in name for p in DIRECT_PII_PARTS) and not is_ref
        sval = "" if v is None else str(v)
        value_is_pii = bool(EMAIL_RE.search(sval)) or sval.lower() in identity_hits.get("hashes", [])
        if is_ref:
            if not is_blank(v):
                refs.append(k)
        elif is_pii_name or value_is_pii:
            (pii if not is_blank(v) else null_pii).append(k)
    return sorted(set(pii)), sorted(set(null_pii)), sorted(set(refs))


def restore_flag(prefix: str, flat: dict) -> bool | None:
    """True = can still be restored, False = restore blocked, None = not said."""
    _, ra = first(flat, RESTORE_KEYS)
    if boolish(ra) is not None:
        return boolish(ra)
    _, blk = first(flat, RESTORE_BLOCK_KEYS)
    _, elig = first(flat, RESTORE_ELIGIBLE_KEYS)
    if boolish(blk) is True:
        return False
    if boolish(elig) is not None:
        return boolish(elig) and boolish(blk) is not True
    if prefix in BACKUP_PREFIXES:
        _, dec = first(flat, RESTORE_DECISION_KEYS)
        dec = str(dec or "").strip().lower()
        if dec in DENY_WORDS:
            return False
        if dec in ALLOW_WORDS:
            return True
    return None


def derive_state(prefix: str, raw_status: str, flat: dict, http_status: int | None,
                 pii: list, refs: list) -> tuple[str, int]:
    """Map raw facts to the handover vocabulary. Returns (state, exists)."""
    s = (raw_status or "").strip().upper().replace("-", "_")
    if http_status in (404, 410) or s in ABSENT_WORDS or s.replace(" ", "_") in ABSENT_WORDS:
        return "NOT_FOUND", 0
    _, en = first(flat, ENABLED_KEYS)
    en, ra = boolish(en), restore_flag(prefix, flat)
    if prefix in FLOW_PREFIXES or en is not None:
        if en is not None:
            return ("ACTIVE" if en else "DISABLED"), 1
        if s in ("ACTIVE", "DISABLED"):
            return s, 1
    if prefix in BACKUP_PREFIXES or ra is not None:
        if ra is not None:
            return ("ACTIVE" if ra else "BLOCKED"), 1
        if s in ("ACTIVE", "BLOCKED"):
            return s, 1
    if s in ("REDACTED", "ANONYMIZED", "IDENTIFIABLE", "FOUND"):
        return s, 1
    # A record that exists: judge from its identifying fields.
    if pii:
        return "FOUND", 1
    if refs:
        return "REDACTED", 1
    return "ANONYMIZED", 1


class Builder:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.rows: list[dict] = []
        self.unmatched = Counter()
        self.pipe_categories: set[str] = set()  # categories named by handover-style lines

    def add(self, *, file: dict, source_type: str, flat: dict, resource_id: str = "",
            raw_system: str = "", category: str = "", raw_status: str = "",
            observed_at: str = "", time_source: str = "", section: str = "",
            http_status: int | None = None, state: str = "", raw_text: str = "",
            is_state: bool = True, lookup_values: list[str] = ()):
        ctx = self.ctx
        lookups = list(lookup_values)
        strong_flat = {}
        for k, v in flat.items():
            if leaf(k) in LOOKUP_KEY_NAMES:
                if not is_blank(v):
                    lookups.append(str(v))
            elif isinstance(v, str):
                lookups += LOOKUP_VALUE_RE.findall(v)
                strong_flat[k] = LOOKUP_VALUE_RE.sub("", v)
            else:
                strong_flat[k] = v
        lookups += LOOKUP_VALUE_RE.findall(raw_text)
        lookups = list(dict.fromkeys(lookups))
        hits = ctx.identity.match_values(strong_flat if flat else LOOKUP_VALUE_RE.sub("", raw_text))
        weak = ctx.identity.match_values(lookups) if lookups else {"user_ids": []}
        pii, null_pii, refs = classify_fields(flat, hits)
        prefix = ctx.prefix_of(resource_id)
        refs_to = sorted({str(v) for k, v in flat.items() if is_reference_field(leaf(k))
                          and ctx.resource_re.fullmatch(str(v or "")) and str(v) != resource_id})
        if not state:
            state, exists = derive_state(prefix, raw_status, flat, http_status, pii, refs)
        else:
            exists = 0 if state == "NOT_FOUND" else 1
        for e in hits["unmatched_emails"]:
            self.unmatched[e] += 1
        if not observed_at:
            observed_at, time_source = file["captured_at"], "file"
        raw = raw_text or json.dumps(flat, default=str, ensure_ascii=False)
        self.rows.append({
            "obs_id": f"obs_{len(self.rows) + 1:06d}",
            "file_id": file["file_id"], "source_type": source_type,
            "origin": file.get("origin", ""), "section": section,
            "file_captured_at": file["captured_at"], "observed_at": observed_at,
            "time_source": time_source, "system_id": ctx.system_for(resource_id, raw_system),
            "raw_system": raw_system, "resource_id": resource_id, "prefix": prefix,
            "category": category, "state": state, "raw_status": raw_status, "exists": exists,
            "http_status": http_status or "", "pii_fields": pii, "null_pii_fields": null_pii,
            "reference_fields": refs,
            **{k: hits[k] for k in ("emails", "hashes", "phones", "user_refs", "user_ids",
                                    "match_routes", "unmatched_emails")},
            "lookup_values": lookups,
            "lookup_user_ids": [u for u in weak["user_ids"] if u not in hits["user_ids"]],
            "ref_resource_ids": refs_to,
            "is_state": int(is_state),
            "raw": raw[:3000],
        })

    # ---- record-shaped dict (SQL row, JSON object, log line, vision record) ----
    def add_record(self, file, source_type, rec: dict, *, ctx_time="", ctx_system="",
                   ctx_category="", section="", http_status=None, time_source_default="file"):
        flat = rec
        _, rid = first(flat, ID_KEYS)
        rid = str(rid) if rid is not None and self.ctx.resource_re.fullmatch(str(rid)) else ""
        if not rid:
            found = self.ctx.resources_in(json.dumps(flat, default=str))
            rid = found[0] if len(found) == 1 else ""
        _, sysv = first(flat, SYSTEM_KEYS)
        _, cat = first(flat, CATEGORY_KEYS)
        _, st = first(flat, STATE_KEYS)
        own_time = ""
        for k in TIME_KEYS:
            _, t = first(flat, (k,))
            if t and iso(t):
                own_time = iso(t)
                break
        observed = own_time or ctx_time
        tsrc = "record" if own_time else (time_source_default if ctx_time else "")
        if http_status is None:  # e.g. {"profile": null, "status_code": 404}
            for k, v in flat.items():
                if leaf(k) in HTTP_KEYS and re.fullmatch(r"\d{3}", str(v).strip()):
                    http_status = int(str(v).strip())
                    break
        self.add(file=file, source_type=source_type, flat=flat, resource_id=rid,
                 raw_system=str(sysv or ctx_system or ""), category=str(cat or ctx_category or ""),
                 raw_status=str(st or ""), observed_at=observed, time_source=tsrc,
                 section=section, http_status=http_status)


# --------------------------------------------------------------------------- parsers
def parse_pipe_lines(b: Builder, file: dict, text: str, source_type: str) -> int:
    n = 0
    for line in text.splitlines():
        if line.count("|") < 4 or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if not iso(parts[0]):  # header row or prose
            continue
        # Handover rows have a resource id in the third column. Pipe-delimited logs
        # (time | LEVEL | service | trace | event | k=v ...) do not; they go to parse_kv_lines.
        if not b.ctx.resource_re.fullmatch(parts[2]):
            continue
        t, system, resource, category, state = parts[:5]
        b.pipe_categories.add(category_key(category))
        ident = " | ".join(parts[5:])
        st = state.upper().replace(" ", "_")
        flat = {"time": t, "system": system, "resource_id": resource, "category": category,
                "state": state, "identifier": ident}
        b.add(file=file, source_type=source_type, flat=flat, resource_id=resource,
              raw_system=system, category=category, raw_status=state,
              observed_at=iso(t), time_source="record",
              state=st if st in CANONICAL_STATES else "", raw_text=line.strip())
        n += 1
    return n


def parse_kv_lines(b: Builder, file: dict, text: str, source_type: str) -> int:
    n = 0
    # Some logs put the lookup key on the request line and the resource id on the
    # result line; carry the key across lines that share a trace id.
    trace_lookups: dict[str, list[str]] = defaultdict(list)
    for line in text.splitlines():
        t_m = TRACE_RE.search(line)
        if t_m:
            trace_lookups[t_m.group(1)] += LOOKUP_VALUE_RE.findall(line)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # key=value pairs, also inside an escaped message="k=\"v\" ..." string,
        # and "key":"value" pairs from JSON-per-line logs.
        unescaped = line.replace('\\"', '"')
        kv = {k: v.strip("\"'") for k, v in KV_RE.findall(unescaped)}
        for k, v in JSON_KV_RE.findall(line):
            kv.setdefault(k, v.strip('"'))
        rids = b.ctx.resources_in(line)
        idents = b.ctx.identity.match_values(line)
        if not kv and not rids and not idents["user_ids"]:
            continue
        http = None
        for key in ("http_status", "status_code", "http", "code", "status"):
            if key in kv and re.fullmatch(r"\d{3}", kv[key]):
                http = int(kv[key])
                break
        if http is None:
            m = HTTP_RE.search(line) or BARE_HTTP_RE.search(line)
            if m:
                http = int(m.group(1))
        t = iso(kv.get("ts") or kv.get("time") or kv.get("timestamp") or line)
        rec = dict(kv)
        rec.setdefault("_line", line)
        t_m = TRACE_RE.search(line)
        carried = trace_lookups.get(t_m.group(1), []) if t_m else []
        targets = rids or [""]
        for rid in targets:
            r = dict(rec)
            if rid:
                r["resource_id"] = rid
            raw_status = kv.get("state") or kv.get("result") or kv.get("lookup_result") or ""
            if raw_status and re.fullmatch(r"\d{3}", raw_status):
                raw_status = ""
            b.add(file=file, source_type=source_type, flat=r, resource_id=rid,
                  raw_system=kv.get("system") or kv.get("service") or "",
                  category=kv.get("category", ""), raw_status=raw_status,
                  observed_at=t, time_source="record" if t else "", http_status=http,
                  raw_text=line, is_state=not REQUEST_EVENT_RE.search(line), lookup_values=carried)
            n += 1
    return n


def parse_text(b: Builder, file: dict, text: str, source_type: str) -> int:
    n = parse_pipe_lines(b, file, text, source_type)
    if n == 0:
        n = parse_kv_lines(b, file, text, source_type)
    return n


def parse_json_file(b: Builder, file: dict, data, source_type: str = "json") -> int:
    ctx = b.ctx
    count = 0

    def has_rid(d: dict) -> bool:
        _, v = first({k: x for k, x in d.items() if not isinstance(x, (dict, list))}, ID_KEYS)
        return v is not None and bool(ctx.resource_re.fullmatch(str(v)))

    def contains_resource(v, key) -> bool:
        if ctx.resource_re.fullmatch(str(key)):
            return True
        if isinstance(v, dict):
            return has_rid(v) or any(contains_resource(x, k) for k, x in v.items()
                                     if isinstance(x, (dict, list)))
        if isinstance(v, list):
            return any(isinstance(x, dict) and contains_resource(x, "") for x in v)
        return False

    def walk(node, c_time, c_sys, c_cat, section, key=""):
        nonlocal count
        if isinstance(node, list):
            # list of bare resource ids under a meaningful key, e.g. "not_found": [...]
            if node and all(isinstance(x, str) for x in node):
                ids = [x for x in node if ctx.resource_re.fullmatch(x)]
                kl = key.lower()
                status = ("NOT_FOUND" if any(w in kl for w in ("not_found", "absent", "deleted",
                                                               "missing", "purged")) else "")
                for rid in ids:
                    b.add(file=file, source_type=source_type,
                          flat={"resource_id": rid, "listed_under": key}, resource_id=rid,
                          raw_system=c_sys, category=c_cat, raw_status=status,
                          observed_at=c_time, time_source="section" if c_time else "",
                          section=section)
                    count += 1
                return
            for i, x in enumerate(node):
                walk(x, c_time, c_sys, c_cat, section, key)
            return
        if not isinstance(node, dict):
            return
        scalars = {k: v for k, v in node.items() if not isinstance(v, (dict, list))}
        n_time, n_sys, n_cat = c_time, c_sys, c_cat
        for k in TIME_KEYS:
            if k in scalars and iso(scalars[k]):
                n_time = iso(scalars[k])
                break
        for k in SYSTEM_KEYS:
            if k in scalars and not is_blank(scalars[k]):
                n_sys = str(scalars[k])
                break
        for k in CATEGORY_KEYS:
            if k in scalars and not is_blank(scalars[k]):
                n_cat = str(scalars[k])
                break
        sec = section
        for k in ("section", "section_id", "name", "snapshot", "system"):
            if k in scalars and not has_rid(node):
                sec = f"{section}/{scalars[k]}" if section else str(scalars[k])
                break

        rid_from_key = key if ctx.resource_re.fullmatch(str(key)) else ""
        if has_rid(node) or rid_from_key:
            flat = flatten(node, skip_resource_children=lambda v, k: contains_resource(v, k))
            if rid_from_key and not has_rid(node):
                flat = {"resource_id": rid_from_key, **flat}
            b.add_record(file, source_type, flat, ctx_time=c_time, ctx_system=c_sys,
                         ctx_category=c_cat, section=section, time_source_default="section")
            count += 1
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                walk(v, n_time, n_sys, n_cat, sec, str(k))

    walk(data, "", "", "", "")
    return count


def parse_sql(b: Builder, file: dict, path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    header = re.search(r"Captured at:?\s*([0-9T:\-\s.Z+]+)", text, re.I)
    header_time = iso(header.group(1)) if header else ""
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(text)
    except sqlite3.Error:
        for stmt in re.split(r";\s*\n", text):
            try:
                con.execute(stmt)
            except sqlite3.Error:
                pass
    con.row_factory = sqlite3.Row
    tables = [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]

    scope: dict[str, str] = {}
    for t in tables:
        if "scope" not in t.lower():
            continue
        for row in con.execute(f'SELECT * FROM "{t}"'):
            d = dict(row)
            when = next((iso(v) for v in d.values() if iso(v)), "")
            for k, v in d.items():
                if isinstance(v, str) and not iso(v) and v and when:
                    scope[v] = when  # system name / table name -> scope time
    n = 0
    for t in tables:
        if "scope" in t.lower():
            continue
        for row in con.execute(f'SELECT * FROM "{t}"'):
            d = dict(row)
            _, sysv = first(d, SYSTEM_KEYS)
            when = scope.get(str(sysv or "")) or scope.get(t) or ""
            tsrc = "snapshot_scope" if when else ("sql_header" if header_time else "")
            b.add_record(file, "sql", {"_table": t, **d}, ctx_time=when or header_time,
                         ctx_system=str(sysv or ""), section=t, time_source_default=tsrc)
            n += 1
    con.close()
    return n


def vision_extract(path: Path, file_id: str, run_id: str) -> dict | None:
    cache_key = f"{PROMPT_VERSION}_{llm_client.file_sha(path)}"
    if not llm_client.available():
        text = llm_client.read_cached(cache_key, purpose="vision_extract", ref=file_id, run_id=run_id)
        return llm_client.parse_json(text) if text else None
    system = (ROOT / "prompts" / "vision_extract.md").read_text(encoding="utf-8")
    text = llm_client.call(
        purpose="vision_extract", ref=file_id, system=system,
        text=f"Evidence file {file_id}. Return the JSON only.", files=[path],
        cache_key=cache_key, run_id=run_id,
    )
    return llm_client.parse_json(text)


def add_vision(b: Builder, file: dict, data: dict, source_type: str) -> int:
    n = 0
    file_time = iso(data.get("captured_or_shown_time", ""))
    for o in data.get("observations", []):
        flags = o.get("flags") or {}
        rec = {
            "resource_id": o.get("resource_id", ""), "system": o.get("system") or data.get("system_shown", ""),
            "category": o.get("category", ""), "status_text": o.get("status_text", ""),
            "names": o.get("names", []), "emails": o.get("emails", []), "phones": o.get("phones", []),
            "email_hash": o.get("email_hashes", []), "user_reference": o.get("user_refs", []),
            "enabled": flags.get("enabled"), "restore_allowed": flags.get("restore_allowed"),
            "legal_hold_active": flags.get("legal_hold_active"),
            "fields_with_values": o.get("fields_with_values", []),
            "fields_blank_or_redacted": o.get("fields_blank_or_redacted", []),
            "notes": o.get("notes", ""),
        }
        rid = rec["resource_id"] if b.ctx.resource_re.fullmatch(rec["resource_id"] or "") else ""
        status = rec["status_text"]
        if o.get("record_exists") is False:
            status = "NOT_FOUND"
        t = iso(o.get("observed_at", "")) or file_time
        hits = b.ctx.identity.match_values(rec)
        # Field-level PII judgement from what the model saw, not from key names.
        pii = list(rec["fields_with_values"]) or (["emails"] if hits["emails"] else [])
        st, _ = derive_state(b.ctx.prefix_of(rid), status,
                             {"enabled": rec["enabled"], "restore_allowed": rec["restore_allowed"]},
                             None, pii, ["user_reference"] if rec["user_reference"] else [])
        b.add(file=file, source_type=source_type, flat=rec, resource_id=rid,
              raw_system=rec["system"], category=rec["category"], raw_status=status,
              observed_at=t, time_source="record" if t else "", state=st)
        n += 1
    return n


def load_manual_visuals(path: Path) -> dict[str, list[dict]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("observations", [])
    by_file = defaultdict(list)
    for o in items:
        by_file[o.get("file_id") or o.get("evidence_id") or ""].append(o)
    return by_file


def manual_to_vision(obs: list[dict]) -> dict:
    """Adapt hand-written observations (time/system/resource/category/state/identifier)."""
    out = []
    for o in obs:
        ident = o.get("identifier") or o.get("identifiers") or ""
        ident_s = json.dumps(ident) if not isinstance(ident, str) else ident
        state = str(o.get("state", ""))
        out.append({
            "observed_at": o.get("time") or o.get("observed_at", ""),
            "system": o.get("system") or o.get("system_id", ""),
            "resource_id": o.get("resource") or o.get("resource_id", ""),
            "category": o.get("category", ""), "status_text": state,
            "record_exists": state.upper() != "NOT_FOUND",
            "emails": EMAIL_RE.findall(ident_s), "names": [o["name"]] if o.get("name") else [],
            "phones": [], "email_hashes": re.findall(r"\b[a-f0-9]{64}\b", ident_s),
            "user_refs": re.findall(r"\buser_\d+\b", ident_s),
            "fields_with_values": ["identifier"] if state.upper() in ("FOUND", "IDENTIFIABLE", "ACTIVE") else [],
            "flags": {}, "notes": o.get("notes", ""),
        })
    return {"observations": out}


def pdf_text(path: Path) -> str:
    try:
        import pdfplumber  # type: ignore
        with pdfplumber.open(path) as pdf:
            return "\n".join((p.extract_text() or "") for p in pdf.pages)
    except Exception:
        pass
    try:
        from pypdf import PdfReader  # type: ignore
        return "\n".join((p.extract_text() or "") for p in PdfReader(str(path)).pages)
    except Exception:
        return ""


# --------------------------------------------------------------------------- links
def extract_links(ctx: Context, files: list[dict]) -> list[dict]:
    """LINK_RESOURCE_IDENTITY events -> resource/email/user/file links."""
    visual = sorted((f for f in files if Path(f["file_path"]).suffix.lower()
                     in (".png", ".jpg", ".jpeg", ".pdf")), key=lambda f: f["captured_at"])
    out = []
    for row in csv.DictReader(open(ctx.dataset / "system_activity.csv", encoding="utf-8")):
        if row["event_type"] != "LINK_RESOURCE_IDENTITY":
            continue
        details = row.get("details", "")
        text = f'{row.get("resource_id", "")} {details}'
        hits = ctx.identity.match_values(details)
        file_ids = re.findall(r"\bevidence_\d+\b", text)
        how = "explicit"
        if not file_ids:
            t = datetime.fromisoformat(iso(row["event_time"]).replace("Z", "+00:00"))
            cands = [f for f in visual if timedelta(0) <= t - datetime.fromisoformat(
                iso(f["captured_at"]).replace("Z", "+00:00")) <= timedelta(minutes=30)]
            if cands:
                file_ids, how = [cands[-1]["file_id"]], "nearest_preceding_visual"
        for rid in ctx.resources_in(text) or [""]:
            out.append({
                "activity_id": row["activity_id"], "event_time": iso(row["event_time"]),
                "resource_id": rid, "system_id": ctx.system_for(rid, row.get("target_system", "")),
                "emails": hits["emails"], "user_ids": hits["user_ids"],
                "match_routes": hits["match_routes"], "unmatched_emails": hits["unmatched_emails"],
                "file_id": file_ids[0] if file_ids else "", "file_link_method": how if file_ids else "",
                "details": details,
            })
    return out


# --------------------------------------------------------------------------- driver
def resolve_path(dataset: Path, rel: str) -> Path | None:
    rel = rel.replace("\\", "/")
    for cand in (dataset / rel, dataset / "evidence" / rel, dataset.parent / rel,
                 dataset / "evidence" / Path(rel).name):
        if cand.exists():
            return cand
    hits = list((dataset / "evidence").rglob(Path(rel).name)) if (dataset / "evidence").exists() else []
    return hits[0] if hits else None


def normalize(dataset: Path, out: Path, visual_fallback: Path | None, run_id: str) -> dict:
    ctx = Context(dataset)
    b = Builder(ctx)
    files = list(csv.DictReader(open(dataset / "evidence_files.csv", encoding="utf-8")))
    for f in files:
        f["captured_at"] = iso(f["captured_at"]) or f["captured_at"]
    manual = load_manual_visuals(visual_fallback) if visual_fallback else {}
    report = []
    for f in files:
        path = resolve_path(dataset, f["file_path"])
        before = len(b.rows)
        status, note = "ok", ""
        if path is None:
            status, note = "missing", f["file_path"]
        else:
            ext = path.suffix.lower()
            try:
                if ext in (".sql", ".sqlite", ".db") or "sql" in ext:
                    parse_sql(b, f, path)
                elif ext == ".json":
                    parse_json_file(b, f, json.loads(path.read_text(encoding="utf-8")))
                elif ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf"):
                    used = ""
                    if ext == ".pdf":
                        text = pdf_text(path)
                        if text.strip() and (ctx.resources_in(text) or EMAIL_RE.search(text)):
                            parse_text(b, f, text, "pdf_text")
                            used = "pdf_text"
                    if not used:
                        try:
                            data = vision_extract(path, f["file_id"], run_id)
                        except Exception as exc:  # rate limit, bad model id, bad JSON
                            data, note = None, f"vision failed: {type(exc).__name__}: {exc}"[:300]
                            print(f"[warn] {f['file_id']}: {note}", file=sys.stderr)
                        if data is not None:
                            add_vision(b, f, data, "vision")
                            used = "vision"
                        elif f["file_id"] in manual:
                            add_vision(b, f, manual_to_vision(manual[f["file_id"]]), "visual_manual")
                            used = "visual_manual"
                        else:
                            status, note = "unread", "no API key, no cache, no manual fallback"
                    note = note or used
                else:  # .txt, .log, anything text
                    parse_text(b, f, path.read_text(encoding="utf-8", errors="replace"),
                               "log" if ext == ".log" or "log" in f["file_path"].lower() else "text")
            except Exception as exc:  # keep going; report it
                status, note = "error", f"{type(exc).__name__}: {exc}"
        report.append({"file_id": f["file_id"], "file_path": f["file_path"], "status": status,
                       "observations": len(b.rows) - before, "note": note})

    # Only real data categories survive; log fields that happen to be called
    # "category" (trace ids, worker names like vault-3) are blanked.
    rules_path = dataset / "deletion_rules.csv"
    allowed = set(b.pipe_categories)
    if rules_path.exists():
        allowed |= {category_key(r.get("data_category", ""))
                    for r in csv.DictReader(open(rules_path, encoding="utf-8"))}
    allowed.discard("")
    dropped_categories = Counter()
    for r in b.rows:
        if r["category"] and category_key(r["category"]) not in allowed:
            dropped_categories[r["category"]] += 1
            r["category"] = ""

    out.mkdir(parents=True, exist_ok=True)
    with open(out / "observations.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=OBS_COLUMNS)
        w.writeheader()
        for r in b.rows:
            w.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, list) else v
                        for k, v in r.items()})
    links = extract_links(ctx, files)
    with open(out / "links.csv", "w", encoding="utf-8", newline="") as fh:
        cols = ["activity_id", "event_time", "resource_id", "system_id", "emails", "user_ids",
                "match_routes", "unmatched_emails", "file_id", "file_link_method", "details"]
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in links:
            w.writerow({k: json.dumps(v) if isinstance(v, list) else v for k, v in r.items()})
    with open(out / "normalize_report.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["file_id", "file_path", "status", "observations", "note"])
        w.writeheader()
        w.writerows(report)
    with open(out / "unmatched_emails.csv", "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["email", "occurrences"])
        w.writerows(b.unmatched.most_common())

    summary = {
        "files": len(files),
        "file_status": dict(Counter(r["status"] for r in report)),
        "observations": len(b.rows),
        "by_source_type": dict(Counter(r["source_type"] for r in b.rows)),
        "by_state": dict(Counter(r["state"] for r in b.rows)),
        "without_resource_id": sum(1 for r in b.rows if not r["resource_id"]),
        "without_system_id": sum(1 for r in b.rows if r["resource_id"] and not r["system_id"]),
        "linked_to_a_user": sum(1 for r in b.rows if r["user_ids"]),
        "linked_to_multiple_users": sum(1 for r in b.rows if len(r["user_ids"]) > 1),
        "unmatched_emails": len(b.unmatched),
        "categories_kept": sorted(allowed),
        "categories_dropped": sum(dropped_categories.values()),
        "links": len(links),
        "prefix_system_map": ctx.prefix_system,
    }
    (out / "normalize_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def score_visual(out: Path, manual_path: Path) -> dict:
    """Compare vision-extracted observations with the hand-read ground truth."""
    manual = load_manual_visuals(manual_path)
    rows = [r for r in csv.DictReader(open(out / "observations.csv", encoding="utf-8"))
            if r["source_type"] == "vision"]
    got = defaultdict(list)
    for r in rows:
        got[r["file_id"]].append(r)
    fields = Counter()
    total = Counter()
    for fid, truth in manual.items():
        for t in manual_to_vision(truth)["observations"]:
            cands = got.get(fid, [])
            match = next((c for c in cands if c["resource_id"] == t["resource_id"]), None) \
                or (cands[0] if len(cands) == 1 else None)
            total["observations"] += 1
            if not match:
                continue
            fields["observation_found"] += 1
            checks = {
                "resource_id": match["resource_id"] == t["resource_id"],
                "emails": set(json.loads(match["emails"])) >= {e.lower() for e in t["emails"]},
                "state": match["state"] == str(t["status_text"]).upper()
                or (str(t["status_text"]).upper() in ("FOUND", "IDENTIFIABLE") and match["state"] in ("FOUND", "IDENTIFIABLE")),
            }
            for k, ok in checks.items():
                total[k] += 1
                fields[k] += int(ok)
    total["observation_found"] = total["observations"]
    res = {k: {"correct": fields[k], "total": total[k],
               "accuracy": round(fields[k] / total[k], 3) if total[k] else None}
           for k in ("observation_found", "resource_id", "emails", "state")}
    (out / "visual_score.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="dataset")
    ap.add_argument("--out", default="build")
    ap.add_argument("--visual-fallback", type=Path, default=None,
                    help="hand-read observations JSON used only when no API key/cache exists")
    ap.add_argument("--score-visual", type=Path, default=None,
                    help="hand-read observations JSON to score vision extraction against")
    ap.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ"))
    a = ap.parse_args()
    summary = normalize(Path(a.dataset), Path(a.out), a.visual_fallback, a.run_id)
    print(json.dumps(summary, indent=2))
    if a.score_visual:
        print(json.dumps(score_visual(Path(a.out), a.score_visual), indent=2))


if __name__ == "__main__":
    main()

"""Identity index: current + historical identifiers for every user.

Built from user_identities.csv and user_audit_log.csv. Matching is exact
(case-insensitive for emails, digits-only for phones). Names are never used
for matching because several users share a name and the evidence contains
near-name decoys.
"""
from __future__ import annotations

import csv
import hashlib
import re
from collections import defaultdict
from pathlib import Path

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
USER_REF_RE = re.compile(r"\buser_\d+\b")
PHONE_RE = re.compile(r"\+?\d[\d\s().\-]{6,}\d")

# Keys whose values are integrity material, never identity.
NON_IDENTITY_KEY_PARTS = ("seal", "integrity", "signature", "checksum", "digest_of_record")

MIN_PHONE_DIGITS = 8


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def _read_csv(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


class IdentityIndex:
    def __init__(self, dataset_dir: str | Path):
        d = Path(dataset_dir)
        self.users: dict[str, dict] = {}
        # identifier value -> list of (user_id, kind)  kind in {current, historical}
        self.by_email: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.by_hash: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.by_phone: dict[str, list[tuple[str, str]]] = defaultdict(list)
        # user_id -> {"emails": set, "hashes": set, "phones": set}
        self.ids: dict[str, dict[str, set]] = defaultdict(
            lambda: {"emails": set(), "hashes": set(), "phones": set()}
        )
        # email -> list of (user_id, valid_from, valid_to) ; '' means open-ended
        self.email_intervals: dict[str, list[tuple[str, str, str]]] = defaultdict(list)

        for u in _read_csv(d / "user_identities.csv"):
            uid = u["user_id"]
            self.users[uid] = u
            self._add_email(uid, u.get("email", ""), "current")
            self._add_hash(uid, u.get("email_hash", ""), "current")
            self._add_phone(uid, u.get("phone", ""), "current")

        audit = sorted(_read_csv(d / "user_audit_log.csv"), key=lambda r: r["event_time"])
        last_change: dict[tuple[str, str], str] = {}
        for a in audit:
            uid, field = a["user_id"], a["field_name"]
            for value in (a.get("old_value", ""), a.get("new_value", "")):
                if field == "email":
                    self._add_email(uid, value, "historical")
                elif field == "email_hash":
                    self._add_hash(uid, value, "historical")
                elif field == "phone":
                    self._add_phone(uid, value, "historical")
            if field == "email" and a.get("old_value"):
                start = last_change.get((uid, field), "")
                self.email_intervals[a["old_value"].strip().lower()].append(
                    (uid, start, a["event_time"])
                )
                last_change[(uid, field)] = a["event_time"]
        for uid, u in self.users.items():
            e = (u.get("email") or "").strip().lower()
            if e:
                self.email_intervals[e].append((uid, last_change.get((uid, "email"), ""), ""))

    # ---- building -------------------------------------------------------
    def _add_email(self, uid: str, email: str, kind: str) -> None:
        e = (email or "").strip()
        if not e or "@" not in e:
            return
        low = e.lower()
        if (uid, kind) not in self.by_email[low]:
            self.by_email[low].append((uid, kind))
        self.ids[uid]["emails"].add(low)
        # evidence may hash the address as stored or lower-cased
        for h in {sha256(e), sha256(low)}:
            self._add_hash(uid, h, kind)

    def _add_hash(self, uid: str, h: str, kind: str) -> None:
        h = (h or "").strip().lower()
        if len(h) != 64:
            return
        if (uid, kind) not in self.by_hash[h]:
            self.by_hash[h].append((uid, kind))
        self.ids[uid]["hashes"].add(h)

    def _add_phone(self, uid: str, phone: str, kind: str) -> None:
        p = digits(phone)
        if len(p) < MIN_PHONE_DIGITS:
            return
        if (uid, kind) not in self.by_phone[p]:
            self.by_phone[p].append((uid, kind))
        self.ids[uid]["phones"].add(p)

    # ---- lookups --------------------------------------------------------
    def canonical_user(self, ref: str) -> str | None:
        """Map 'user_7' / 'user_07' / 'user_007' to the user_id used in user_identities."""
        if ref in self.users:
            return ref
        m = re.fullmatch(r"user_0*(\d+)", ref or "")
        if not m:
            return None
        if not hasattr(self, "_by_num"):
            self._by_num = {}
            for uid in self.users:
                n = re.fullmatch(r"user_0*(\d+)", uid)
                if n:
                    self._by_num[int(n.group(1))] = uid
        return self._by_num.get(int(m.group(1)))

    def resolve_email(self, email: str, at: str = "") -> str | None:
        """User who held `email` at time `at` (ISO string); falls back to any holder."""
        low = (email or "").strip().lower()
        spans = self.email_intervals.get(low, [])
        if at:
            for uid, start, end in spans:
                if (not start or start <= at) and (not end or at < end):
                    return uid
        holders = {u for u, _ in self.by_email.get(low, [])}
        return next(iter(holders)) if len(holders) == 1 else (spans[-1][0] if spans else None)

    def match_values(self, values: dict | list | str) -> dict:
        """Scan a record (dict of fields, list, or text) for identifiers.

        Returns emails/hashes/phones/user_refs found, the user_ids they resolve
        to, how each resolved, and emails that matched nobody (decoys).
        """
        found = {"emails": set(), "hashes": set(), "phones": set(), "user_refs": set()}

        def scan_text(text: str, key: str = "") -> None:
            if any(p in key.lower() for p in NON_IDENTITY_KEY_PARTS):
                return
            for m in EMAIL_RE.findall(text):
                found["emails"].add(m.lower())
            for m in HASH_RE.findall(text):
                found["hashes"].add(m.lower())
            for m in USER_REF_RE.findall(text):
                found["user_refs"].add(m)
            for m in PHONE_RE.findall(text):
                p = digits(m)
                if len(p) >= MIN_PHONE_DIGITS:
                    found["phones"].add(p)

        def walk(node, key=""):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, str(k))
            elif isinstance(node, (list, tuple, set)):
                for v in node:
                    walk(v, key)
            elif node is not None:
                scan_text(str(node), key)

        walk(values)

        user_ids, routes, unmatched = set(), set(), set()
        for e in found["emails"]:
            hits = self.by_email.get(e)
            if hits:
                for uid, kind in hits:
                    user_ids.add(uid)
                    routes.add(f"email_{kind}")
            else:
                unmatched.add(e)
        for h in found["hashes"]:
            for uid, kind in self.by_hash.get(h, []):
                user_ids.add(uid)
                routes.add(f"hash_{kind}")
        for p in found["phones"]:
            for uid, kind in self.by_phone.get(p, []):
                user_ids.add(uid)
                routes.add(f"phone_{kind}")
        for r in found["user_refs"]:
            uid = self.canonical_user(r)
            if uid:
                user_ids.add(uid)
                routes.add("user_ref")
        # Hashes/phones that resolve to nobody are not identity (e.g. seals, timestamps).
        found["hashes"] = {h for h in found["hashes"] if h in self.by_hash}
        found["phones"] = {p for p in found["phones"] if p in self.by_phone}
        return {
            **{k: sorted(v) for k, v in found.items()},
            "user_ids": sorted(user_ids),
            "match_routes": sorted(routes),
            "unmatched_emails": sorted(unmatched),
        }

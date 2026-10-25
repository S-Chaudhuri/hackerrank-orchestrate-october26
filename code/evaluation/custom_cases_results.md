# Custom evaluation cases

| Case | Scenario | Result | Detail |
|---|---|---|---|
| custom_01 | Request email in upper case (case_09 subject) | PASS | INCOMPLETE |
| custom_02 | Historical email after an email change (user_11) | PASS | INCOMPLETE |
| custom_03 | Non-deletion request in Spanish | FAIL | status INCOMPLETE != NOT_APPLICABLE; 3 steps, expected none |
| custom_04 | Audit before the deletion: no evidence from the future | PASS | COMPLETE |
| custom_05 | Look-alike decoy in the same search result | PASS | INCOMPLETE |

4/5 passed.

## custom_01: Request email in upper case (case_09 subject)

Email matching must be case-insensitive; the answer must equal sample case_09 (backup_4978 restorable in evidence_93).

Predicted `INCOMPLETE`: `[{"step_no":1,"phase":"FINDING","system_id":"backup_service","resource_id":"backup_4978","operation":"REPORT_RESTORE_RISK","state":"ACTIVE","evidence_id":"evidence_93"},{"step_no":2,"phase":"REMEDIATION","system_id":"backup_service","resource_id":"backup_4978","operation":"BLOCK_RESTORE","state":"BLOCKED","evidence_id":""},{"step_no":3,"phase":"VERIFICATION","system_id":"backup_service","resource_id":"backup_4978","operation":"VERIFY_RESTORE_BLOCKED","state":"BLOCKED","evidence_id":""}]`

## custom_02: Historical email after an email change (user_11)

audit_277 changed user_11's email on 2026-05-17; the account admin screenshot evidence_04 (2026-09-26) still shows account_5762 with name, email and phone.

Predicted `INCOMPLETE`: `[{"step_no":1,"phase":"FINDING","system_id":"account_service","resource_id":"account_5762","operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":"evidence_04"},{"step_no":2,"phase":"REMEDIATION","system_id":"account_service","resource_id":"account_5762","operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""},{"step_no":3,"phase":"VERIFICATION","system_id":"account_service","resource_id":"account_5762","operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""},{"step_no":4,"phase":"VERIFICATION","system_id":"security_service","resource_id":"audit_record_3753","operation":"VERIFY_RECORD_PRESENT","state":"PRESENT","evidence_id":""},{"step_no":5,"phase":"VERIFICATION","system_id":"support_platform","resource_id":"support_9538","operation":"VERIFY_RECORD_REDACTED","state":"REDACTED","evidence_id":""}]`

## custom_03: Non-deletion request in Spanish

The person asks for an address update and explicitly says not to delete anything.

Predicted `INCOMPLETE`: `[{"step_no":1,"phase":"FINDING","system_id":"search_service","resource_id":"search_428","operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":"evidence_09"},{"step_no":2,"phase":"REMEDIATION","system_id":"search_service","resource_id":"search_428","operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""},{"step_no":3,"phase":"VERIFICATION","system_id":"search_service","resource_id":"search_428","operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""}]`

## custom_04: Audit before the deletion: no evidence from the future

Same subject as sample case_03, audited a day before the 2026-09-15 deletion run. evidence_94 (2026-09-26) proves case_03's answer but must not be used here.

Predicted `COMPLETE`: `[]`

## custom_05: Look-alike decoy in the same search result

The search console screenshot evidence_09 (2026-09-01) shows search_428 for g.silva76@gmail.com (user_13) and search_1874 for g.silva76.jr@gmail.com, a different person.

Predicted `INCOMPLETE`: `[{"step_no":1,"phase":"FINDING","system_id":"search_service","resource_id":"search_428","operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":"evidence_09"},{"step_no":2,"phase":"REMEDIATION","system_id":"search_service","resource_id":"search_428","operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""},{"step_no":3,"phase":"VERIFICATION","system_id":"search_service","resource_id":"search_428","operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""}]`

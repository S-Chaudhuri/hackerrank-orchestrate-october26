# Score report

| Metric | Value |
|---|---|
| cases | 32 |
| status_accuracy | 1.0 |
| json_valid | 1.0 |
| step_numbering_ok | 1.0 |
| step_precision | 0.9576 |
| step_recall | 0.8187 |
| step_f1 | 0.8827 |
| resource_precision | 0.9753 |
| resource_recall | 0.7117 |
| field_accuracy.key | 0.8187 |
| field_accuracy.phase | 0.8187 |
| field_accuracy.state | 0.8187 |
| field_accuracy.evidence_id | 0.8187 |
| sequence_exact | 0.25 |
| sequence_similarity | 0.7053 |
| pred_steps | 165 |
| gold_steps | 193 |

## Cases not exactly right (24)

### case_01: gold COMPLETE, predicted COMPLETE, sequence similarity 0.0
- missing: `VERIFICATION | account_service | account_001 | VERIFY_RECORD_ABSENT | ABSENT | evidence_54`

### case_02: gold COMPLETE, predicted COMPLETE, sequence similarity 0.0
- missing: `VERIFICATION | account_service | account_002 | VERIFY_RECORD_ABSENT | ABSENT | evidence_54`

### case_03: gold COMPLETE, predicted COMPLETE, sequence similarity 0.667
- missing: `VERIFICATION | analytics_platform | analytics_9406 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | evidence_94`

### case_04: gold COMPLETE, predicted COMPLETE, sequence similarity 0.0
- missing: `VERIFICATION | account_service | account_004 | VERIFY_RECORD_ABSENT | ABSENT | evidence_54`
- missing: `VERIFICATION | analytics_platform | analytics_901 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | evidence_56`

### case_07: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.5
- missing: `VERIFICATION | account_service | account_007 | VERIFY_RECORD_ABSENT | ABSENT | `
- extra: `FINDING | support_platform | object_19 | REPORT_REMAINING_RECORD | PRESENT | evidence_46`
- extra: `REMEDIATION | support_platform | object_19 | DELETE_RECORD | ABSENT | `
- extra: `VERIFICATION | support_platform | object_19 | VERIFY_RECORD_ABSENT | ABSENT | `

### case_08: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.75
- missing: `VERIFICATION | account_service | account_008 | VERIFY_RECORD_ABSENT | ABSENT | `

### case_09: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.6
- missing: `VERIFICATION | account_service | account_3960 | VERIFY_RECORD_ABSENT | ABSENT | `
- missing: `VERIFICATION | security_service | audit_record_4902 | VERIFY_RECORD_PRESENT | PRESENT | `

### case_10: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.75
- missing: `VERIFICATION | account_service | account_010 | VERIFY_RECORD_ABSENT | ABSENT | `

### case_12: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.2
- missing: `FINDING | analytics_platform | analytics_9914 | REPORT_REMAINING_RECORD | PRESENT | evidence_01`
- missing: `REMEDIATION | analytics_platform | analytics_9914 | DELETE_RECORD | ABSENT | `
- missing: `VERIFICATION | analytics_platform | analytics_9914 | VERIFY_RECORD_ABSENT | ABSENT | `
- extra: `FINDING | analytics_platform | analytics_9914 | REPORT_EXPOSED_PII | PRESENT | evidence_01`
- extra: `REMEDIATION | analytics_platform | analytics_9914 | ANONYMIZE_RECORD | ANONYMIZED | `
- extra: `VERIFICATION | analytics_platform | analytics_9914 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | `

### case_17: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.833
- extra: `VERIFICATION | identity_service | tombstone_17 | VERIFY_RECORD_REDACTED | REDACTED | `

### case_18: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.857
- missing: `VERIFICATION | account_service | account_5521 | VERIFY_RECORD_ABSENT | ABSENT | `
- missing: `VERIFICATION | security_service | audit_record_6645 | VERIFY_RECORD_PRESENT | PRESENT | `

### case_20: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.75
- missing: `VERIFICATION | account_service | account_5037 | VERIFY_RECORD_ABSENT | ABSENT | `
- missing: `VERIFICATION | security_service | audit_record_5569 | VERIFY_RECORD_PRESENT | PRESENT | `

### case_21: gold COMPLETE, predicted COMPLETE, sequence similarity 0.333
- missing: `VERIFICATION | account_service | account_6440 | VERIFY_RECORD_ABSENT | ABSENT | evidence_92`
- missing: `VERIFICATION | analytics_platform | analytics_5335 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | evidence_92`

### case_22: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.875
- missing: `VERIFICATION | account_service | account_4990 | VERIFY_RECORD_ABSENT | ABSENT | `

### case_23: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.75
- missing: `VERIFICATION | account_service | account_410 | VERIFY_RECORD_ABSENT | ABSENT | `
- missing: `VERIFICATION | security_service | audit_record_4128 | VERIFY_RECORD_PRESENT | PRESENT | `

### case_24: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.857
- missing: `VERIFICATION | security_service | audit_record_7095 | VERIFY_RECORD_PRESENT | PRESENT | `

### case_25: gold COMPLETE, predicted COMPLETE, sequence similarity 0.333
- missing: `VERIFICATION | account_service | account_3136 | VERIFY_RECORD_ABSENT | ABSENT | evidence_92`
- missing: `VERIFICATION | analytics_platform | analytics_1895 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | evidence_92`

### case_26: gold COMPLETE, predicted COMPLETE, sequence similarity 0.833
- missing: `VERIFICATION | analytics_platform | analytics_4566 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | evidence_92`

### case_27: gold COMPLETE, predicted COMPLETE, sequence similarity 0.833
- missing: `VERIFICATION | analytics_platform | analytics_4574 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | evidence_92`

### case_28: gold COMPLETE, predicted COMPLETE, sequence similarity 0.667
- missing: `VERIFICATION | account_service | account_5482 | VERIFY_RECORD_ABSENT | ABSENT | evidence_92`
- missing: `VERIFICATION | analytics_platform | analytics_6077 | VERIFY_RECORD_ANONYMIZED | ANONYMIZED | evidence_92`

### case_29: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.857
- missing: `VERIFICATION | account_service | account_7012 | VERIFY_RECORD_ABSENT | ABSENT | `
- missing: `VERIFICATION | security_service | audit_record_3954 | VERIFY_RECORD_PRESENT | PRESENT | `

### case_30: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.857
- missing: `VERIFICATION | account_service | account_4163 | VERIFY_RECORD_ABSENT | ABSENT | `
- missing: `VERIFICATION | security_service | audit_record_1707 | VERIFY_RECORD_PRESENT | PRESENT | `

### case_31: gold COMPLETE, predicted COMPLETE, sequence similarity 0.667
- missing: `VERIFICATION | account_service | account_4857 | VERIFY_RECORD_ABSENT | ABSENT | evidence_51`

### case_32: gold INCOMPLETE, predicted INCOMPLETE, sequence similarity 0.8
- missing: `VERIFICATION | account_service | account_8858 | VERIFY_RECORD_ABSENT | ABSENT | `

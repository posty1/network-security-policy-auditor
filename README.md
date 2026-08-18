# Network Security Policy Auditor

A Python command-line tool that reviews exported firewall-policy records and highlights common high-risk patterns before a change is approved.

## What it checks

- Broad source or destination scopes
- `any` service rules
- Missing business owner or ticket reference
- Temporary rules past their expiration date
- Rules with logging disabled

## Run it

```bash
python3 policy_auditor.py sample_rules.json
```

The sample data is synthetic. This project is designed as a portfolio example and does not contain employer configuration or data.

## Example output

```text
[HIGH] FW-102: broad source scope; service is any; logging is disabled
[MEDIUM] FW-103: temporary rule expired on 2025-01-01
```

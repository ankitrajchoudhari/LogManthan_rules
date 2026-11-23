# Security

## Reporting a problem
Report security issues privately using GitHub's **"Report a vulnerability"** button
(Security tab → Advisories) on this repository. Please don't open a public issue for:
- a leaked secret or a real address that slipped into the history
- a rule that could be abused, or a bypass for a rule

## Never commit
- **Secrets:** tokens, passwords, API keys, `.env`, `*.key`, `*.pem`.
  gitleaks runs as a pre-commit hook and in CI on the full history.
- **Real network details:** real IPs, hostnames, usernames, client or company names.
  Use `203.0.113.0/24` (documentation range) in tests and `10.10.1.0/24` in the lab only. The lab
  captures in `tests/suricata/lab/` (and their `lab` address-group set) carry lab addresses.
  Site values for the address groups (`OT_NET`, `OT_WRITERS`, `ENG_WS`, `DNP3_MASTERS`, `IT_NET`)
  live outside this repo.
- **Third-party captures:** they are downloaded at test time and verified by SHA-256.
  Only original lab captures under `tests/suricata/lab/` may be committed.
  Only CC BY / MIT / BSD datasets are used; never NC or unlicensed ones.

## Rule safety
- OT rules are **alert-only**: no `drop`, `reject` or `pass`, and nothing auto-isolates.
- Lua rules are banned. The test runner also passes `security.lua.allow-rules=false`.

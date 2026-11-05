# Krayin Email-Attachment Storage — Inert Verifier

An inert regression verifier for the authenticated Krayin mail-composer path. It uploads random plain text under a `.php` filename and checks the returned storage path from a separate unauthenticated session. **It contains no PHP code and never attempts command execution.**

- **Tested research snapshot:** `a2c1960`
- **Storage fix:** [v2.2.5](https://github.com/krayin/laravel-crm/releases/tag/v2.2.5), including [commit `4d81895`](https://github.com/krayin/laravel-crm/commit/4d818957bd5e32abef89d4708438f55a007fa8b5)
- **Scope:** this verifier tests only the authenticated composer path. The research also traced an external-sender IMAP path to the same repository sink.

[CVE-2026-36340](https://github.com/advisories/GHSA-32px-ccfx-cxq3) describes related composer RCE; it is not presented here as an identifier assigned to this research.

## Run

Use only against an authorized, disposable Krayin lab. Requires Python 3.9+ and a lab account with `mail.compose` access.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 poc_safe_verify.py \
  --target http://127.0.0.1:8000 \
  --email researcher@example.test \
  --acknowledge-authorized-testing
```

The password is requested through a hidden prompt. Use `--insecure` only for a self-signed lab endpoint.

| Exit | Meaning |
|---:|---|
| `1` | The inert marker was publicly retrievable. |
| `0` | The tested public-storage exposure was not observed. |
| `2` | The result was erroneous or inconclusive. |

No result from this verifier demonstrates PHP execution or proves the installation fully patched. The script creates a draft; delete the draft and attachment after testing using the printed identifiers. Upgrading does not remove legacy public attachments.

Research: **Gurpreet Shergill** (`giki-shergill`).

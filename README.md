# Krayin Email-Attachment RCE PoC

End-to-end proof of concept for the authenticated Krayin mail-composer path. The script logs in, uploads a PHP attachment through `POST /admin/mail/create`, extracts the returned public-storage URL, and requests it with `c=id` to demonstrate command execution.

The broader research also traced an external-sender IMAP route to the same vulnerable attachment repository. This published PoC exercises the authenticated composer path.

- **Runtime-tested snapshot:** `a2c1960`
- **Storage fix:** [v2.2.5](https://github.com/krayin/laravel-crm/releases/tag/v2.2.5), including [commit `4d81895`](https://github.com/krayin/laravel-crm/commit/4d818957bd5e32abef89d4708438f55a007fa8b5)
- **Impact:** command execution as the web-server user when the deployment executes PHP beneath `/storage`

## Usage

Run only in an authorized, disposable Krayin lab. The script prompts for the selected lab account's password and does not store it.

```bash
bash poc.sh http://127.0.0.1:8000 admin

# Restricted SalesRep lab account described in the research:
bash poc.sh http://127.0.0.1:8000 sales
```

The script first runs `id`. The uploaded PHP accepts another command through the `c` query parameter. It leaves an executable attachment behind, so delete the draft and `evil.php` from public storage immediately after testing.

Research: **Gurpreet Shergill** (`giki-shergill`).

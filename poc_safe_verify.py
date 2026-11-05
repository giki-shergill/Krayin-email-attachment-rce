#!/usr/bin/env python3
"""Inert upload verifier for the Krayin attachment report.

No PHP code or command payload is uploaded. The test creates one draft email in
an authorized lab and checks whether an inert .php-named marker becomes public.
"""

import argparse
import getpass
import secrets
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urlparse

import requests


class CsrfParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.token = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "input":
            return
        values = dict(attrs)
        if values.get("name") == "_token" and values.get("value"):
            self.token = values["value"]


def require_http_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("target must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise argparse.ArgumentTypeError("target must not contain embedded credentials")
    if parsed.params or parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError(
            "target must not contain URL parameters, a query string, or a fragment"
        )
    return parsed._replace(path=parsed.path.rstrip("/")).geturl()


def find_public_url(value, filename):
    if isinstance(value, str):
        path = unquote(urlparse(value).path)
        if "/storage/emails/" in path and path.rsplit("/", 1)[-1] == filename:
            return value
    if isinstance(value, dict):
        for child in value.values():
            found = find_public_url(child, filename)
            if found:
                return found
    if isinstance(value, list):
        for child in value:
            found = find_public_url(child, filename)
            if found:
                return found
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=require_http_url)
    parser.add_argument("--email", required=True, help="Authorized Krayin lab account")
    parser.add_argument("--recipient", default="lab-recipient@example.invalid")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument(
        "--acknowledge-authorized-testing",
        action="store_true",
        help="Confirm that this is an authorized disposable lab",
    )
    args = parser.parse_args()
    if not args.acknowledge_authorized_testing:
        parser.error("--acknowledge-authorized-testing is required")

    try:
        password = getpass.getpass("Krayin lab password: ")
    except (EOFError, KeyboardInterrupt):
        print("\nCould not read the lab password securely.", file=sys.stderr)
        return 2
    if not password:
        print("Lab password must not be empty.", file=sys.stderr)
        return 2

    verify_tls = not args.insecure
    session = requests.Session()

    login_page = session.get(f"{args.target}/admin/login", timeout=15, verify=verify_tls)
    login_page.raise_for_status()
    csrf_parser = CsrfParser()
    csrf_parser.feed(login_page.text)
    if not csrf_parser.token:
        print("Could not locate login CSRF token", file=sys.stderr)
        return 2

    login = session.post(
        f"{args.target}/admin/login",
        data={"_token": csrf_parser.token, "email": args.email, "password": password},
        timeout=15,
        verify=verify_tls,
    )
    print(f"Login request: HTTP {login.status_code}")
    login.raise_for_status()
    if urlparse(login.url).path.rstrip("/").endswith("/admin/login"):
        print("Login did not leave the login page", file=sys.stderr)
        return 2

    xsrf_cookie = session.cookies.get("XSRF-TOKEN")
    if not xsrf_cookie:
        print("Authenticated session did not provide XSRF-TOKEN", file=sys.stderr)
        return 2

    nonce = secrets.token_hex(8)
    filename = f"krayin-safe-proof-{nonce}.php"
    marker = f"KRAYIN_INERT_UPLOAD_PROOF_{nonce}".encode()
    print(f"Lab cleanup filename: {filename} (if the upload succeeds)")
    headers = {
        "X-XSRF-TOKEN": unquote(xsrf_cookie),
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    }
    upload = session.post(
        f"{args.target}/admin/mail/create",
        headers=headers,
        data={
            "reply_to[]": args.recipient,
            "reply": "Authorized inert attachment regression test",
            "is_draft": "1",
            "source": "web",
        },
        files={"attachments[]": (filename, marker, "application/octet-stream")},
        timeout=20,
        verify=verify_tls,
    )
    print(f"Draft upload: HTTP {upload.status_code}")
    upload.raise_for_status()
    try:
        payload = upload.json()
    except ValueError:
        print("RESULT: INCONCLUSIVE — upload did not return JSON.")
        return 2
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict) or not isinstance(data.get("attachments"), list):
        print("RESULT: INCONCLUSIVE — missing email attachment data.")
        return 2
    print(f"Lab cleanup draft ID: {data.get('id', 'not returned')}")
    if not any(
        isinstance(item, dict) and item.get("name") == filename
        for item in data["attachments"]
    ):
        print("RESULT: INCONCLUSIVE — uploaded marker was not identified in the response.")
        return 2
    public_url = find_public_url(data["attachments"], filename)
    if not public_url:
        print("RESULT: no public .php marker URL was returned; execution was not tested.")
        return 0

    parsed_public = urlparse(public_url)
    # APP_URL may differ from the lab's actual address. Keep the requested
    # target origin, but use the returned attachment path.
    fetch_url = urlparse(args.target)._replace(
        path=parsed_public.path, params="", query="", fragment=""
    ).geturl()
    with requests.Session() as anonymous:
        anonymous.trust_env = False  # No ambient .netrc authentication.
        retrieval = anonymous.get(
            fetch_url, timeout=15, verify=verify_tls, allow_redirects=False
        )
    marker_visible = retrieval.status_code == 200 and marker in retrieval.content

    print(f"Unauthenticated retrieval: HTTP {retrieval.status_code}")
    print(f"Inert marker visible: {'yes' if marker_visible else 'no'}")
    print("No PHP code or command payload was uploaded.")
    print(f"Lab cleanup required for attachment: {filename}")

    if marker_visible:
        print("RESULT: VULNERABLE STORAGE BEHAVIOR OBSERVED.")
        return 1
    print("RESULT: marker was not retrieved; PHP execution was not tested.")
    return 0 if retrieval.status_code in {200, 401, 403, 404} else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        raise SystemExit(2)

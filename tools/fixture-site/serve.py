#!/usr/bin/env python3
"""Local fixture site for manually testing WebGuard against known configurations.

Each page sends a deliberate set of security headers and page content so you can check that the
extension reports exactly the expected findings. Standard library only.

    python3 tools/fixture-site/serve.py                # http://localhost:8443
    python3 tools/fixture-site/serve.py --https        # https://localhost:8443 (self-signed)

Plain HTTP on localhost makes WEB-007/WEB-002/WEB-004 "not applicable", so use --https to exercise
HSTS and mixed content. Chrome will warn about the self-signed certificate; proceed past it for
local testing only. Insecure resource URLs use the reserved ``.invalid`` TLD and never resolve.
"""

import argparse
import contextlib
import html
import shutil
import ssl
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

PAGES: dict[str, dict[str, object]] = {
    "/good": {
        "title": "Well-configured page",
        "expect": "No findings (all checks PASS).",
        "headers": GOOD_HEADERS,
        "body": "<p>This page sends a full set of security headers.</p>",
    },
    "/bad": {
        "title": "Poorly configured page",
        "expect": (
            "HTTPS: WEB-001, WEB-004 (MEDIUM); WEB-002, WEB-003, WEB-005, WEB-006 (LOW). "
            "HTTP: WEB-001 (MEDIUM); WEB-003, WEB-005, WEB-006 (LOW); WEB-002/004/007 n/a."
        ),
        "headers": {"Strict-Transport-Security": "max-age=300", "Referrer-Policy": "unsafe-url"},
        "body": """
<p>Missing CSP, nosniff and framing protection; short HSTS; leaky referrer policy.</p>
<script src="http://cdn.insecure.invalid/legacy.js?session=should-be-stripped"></script>
<img src="http://images.insecure.invalid/logo.png" alt="">
<form action="http://login.insecure.invalid/submit"><button>Sign in</button></form>
""",
    },
    "/weak-csp": {
        "title": "Weak CSP and obsolete X-Frame-Options",
        "expect": "WEB-008 (LOW: unsafe-inline, unsafe-eval), WEB-005 MISCONFIGURED (ALLOW-FROM).",
        "headers": {
            **GOOD_HEADERS,
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' "
            "'unsafe-eval'",
            "X-Frame-Options": "ALLOW-FROM https://partner.example",
        },
        "body": "<p>CSP allows inline scripts and eval.</p>",
    },
    "/meta-csp": {
        "title": "CSP via meta tag only",
        "expect": "WEB-001 PASS via <meta>; WEB-005 MISSING (meta frame-ancestors is ignored).",
        "headers": {
            k: v
            for k, v in GOOD_HEADERS.items()
            if k not in ("Content-Security-Policy", "X-Frame-Options")
        },
        "head": '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
        'frame-ancestors \'none\'"><meta name="referrer" content="no-referrer">',
        "body": "<p>The CSP is delivered in a &lt;meta&gt; tag.</p>",
    },
    "/no-head": {
        "title": "HEAD not allowed",
        "expect": "Same as /good; the collector falls back from HEAD (405) to GET.",
        "headers": GOOD_HEADERS,
        "reject_head": True,
        "body": "<p>This endpoint rejects HEAD requests with 405.</p>",
    },
}


def render(path: str, page: dict[str, object]) -> bytes:
    head = page.get("head", "")
    links = "".join(f'<li><a href="{p}">{p}</a></li>' for p in PAGES)
    title = html.escape(str(page["title"]))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{title}</title>{head}</head>
<body>
<h1>WebGuard fixture: {html.escape(path)}</h1>
<p><strong>Expected:</strong> {html.escape(str(page["expect"]))}</p>
{page["body"]}
<h2>Fixture pages</h2><ul>{links}</ul>
</body></html>""".encode()


INDEX = {
    "title": "WebGuard fixture site",
    "expect": "Open a page below and run a WebGuard scan on it.",
    "headers": GOOD_HEADERS,
    "body": "",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "WebGuardFixture"
    sys_version = ""

    def _page(self) -> tuple[str, dict[str, object]] | None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            return path, INDEX
        page = PAGES.get(path)
        return (path, page) if page else None

    def _respond(self, include_body: bool) -> None:
        found = self._page()
        if found is None:
            self.send_error(404)
            return
        path, page = found
        if not include_body and page.get("reject_head"):
            self.send_response(405)
            self.send_header("Allow", "GET")
            self.end_headers()
            return
        body = render(path, page)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in dict(page["headers"]).items():  # type: ignore[call-overload]
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def do_HEAD(self) -> None:
        self._respond(include_body=False)


def self_signed_context(directory: Path) -> ssl.SSLContext:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise SystemExit("--https needs the openssl command-line tool on PATH.")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(  # noqa: S603 - fixed arguments, local dev tool
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "7",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument(
        "--https", action="store_true", help="serve over HTTPS with a self-signed cert"
    )
    args = parser.parse_args()

    # Bind to loopback only: this server intentionally serves insecure configurations.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    scheme = "http"
    with tempfile.TemporaryDirectory() as tmp:
        if args.https:
            server.socket = self_signed_context(Path(tmp)).wrap_socket(
                server.socket, server_side=True
            )
            scheme = "https"
        print(f"WebGuard fixture site on {scheme}://localhost:{args.port}/  (Ctrl+C to stop)")
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()


if __name__ == "__main__":
    main()

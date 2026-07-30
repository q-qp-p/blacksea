#!/usr/bin/env python3
"""vaultkeeper — CI secrets-sync status service.

A small stdlib-only HTTP front end that reports this sync node's cache state to
the sync fleet.

When VAULTKEEPER_DEBUG_BUNDLE=1 it additionally mirrors the node's secrets cache
under /debug/, so on-call can pull the cached vault and the decryptor without
shelling into the box. That flag is meant for on-fleet nodes only; it is set
from the node's unit file (see ExecStart environment).
"""

import glob
import html
import json
import os
import pathlib
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(os.environ.get("VAULTKEEPER_ROOT", "/srv/vaultkeeper"))
BIND = os.environ.get("VAULTKEEPER_HTTP_BIND", "0.0.0.0")
PORT = int(os.environ.get("VAULTKEEPER_HTTP_PORT", "8080"))
BROKER = os.environ.get("VAULTKEEPER_BROKER", "vault-broker.internal:8200")
SYNC_INTERVAL = int(os.environ.get("VAULTKEEPER_SYNC_INTERVAL", "300"))
DEBUG_BUNDLE = os.environ.get("VAULTKEEPER_DEBUG_BUNDLE", "0") == "1"

PREFIX = "/debug"
VAULT = "secrets/github.pwc"

NODE = {
    "service": "vaultkeeper",
    "role": "secrets-sync",
    "node": "ci-sync-03",
    "version": "1.7.4",
    "environment": "production",
}


def _decryptors():
    # The release cache ships one decryptor per platform; discover them by glob so
    # the node publishes whatever set was actually staged (amd64/arm64/macos).
    return sorted(os.path.basename(p) for p in glob.glob(str(ROOT / "pwcrypt_*"))
                  if os.path.isfile(p))


DECRYPTORS = _decryptors()

# Bundle route table: url -> path under ROOT. An explicit allowlist — nothing
# joins a request-supplied path onto the root. Every staged per-platform
# decryptor is published, so a puller on any OS/arch can grab the one that
# matches their machine.
BUNDLE = {PREFIX + "/README.md": "README.md",
          PREFIX + "/" + VAULT: VAULT,
          PREFIX + "/secrets/.bash_history": "secrets/.bash_history"}
for _d in DECRYPTORS:
    BUNDLE[PREFIX + "/" + _d] = _d


def _dirs():
    # The bundle is a plain mirror of the cache directory, so each URL directory
    # lists the files under it plus its subdirectories.
    dirs = {}
    for url, rel in BUNDLE.items():
        parent, name = url.rsplit("/", 1)
        dirs.setdefault(parent, {})[name] = rel
    for url in list(dirs):
        if url != PREFIX:
            parent, name = url.rsplit("/", 1)
            dirs.setdefault(parent, {})[name + "/"] = url[len(PREFIX) + 1:]
    return dirs


DIRS = _dirs()


def _ctype(rel):
    if rel.endswith(".md") or rel.endswith("_history"):
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


def _last_sync():
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ",
                             time.gmtime((ROOT / VAULT).stat().st_mtime))
    except OSError:
        return None


class VaultkeeperHandler(BaseHTTPRequestHandler):
    server_version = "vaultkeeper/1.7.4"
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    def version_string(self):
        # Product token only — the fleet scrapers key off it, and the default
        # would append the interpreter version to every response.
        return self.server_version

    def _send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, separators=(",", ":")).encode() + b"\n",
                   "application/json")

    def _file(self, url, rel):
        try:
            body = (ROOT / rel).read_bytes()
        except OSError:
            self._json(503, {"error": "bundle_unavailable", "file": rel})
            return
        self._audit(url, len(body))
        self._send(200, body, _ctype(rel))

    def _audit(self, url, nbytes):
        # Debug-bundle pulls are audited: the fleet scrapers only read
        # /v1/sync/status, so anything reaching /debug/ is a human (or something
        # acting like one).
        sys.stderr.write(
            '[audit] BUNDLE FETCH src=%s path=%s bytes=%d ua="%s"\n'
            % (self.client_address[0], url, nbytes,
               self.headers.get("User-Agent", "-"))
        )
        sys.stderr.flush()

    # -- routes ------------------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        raw = self.path.split("?", 1)[0]
        path = raw.rstrip("/") or "/"

        if path == "/":
            self._json(200, NODE)
        elif path == "/healthz":
            self._json(200, {"status": "ok"})
        elif path == "/v1/sync/status":
            # The sync fleet polls this to learn each node's cache state; on a debug
            # node it also advertises where the bundle can be pulled.
            self._json(200, {
                "node": NODE["node"],
                "broker": BROKER,
                "vault": VAULT,
                "decryptors": DECRYPTORS,
                "last_sync": _last_sync(),
                "sync_interval": SYNC_INTERVAL,
                "cache": "warm",
                "debug_bundle": PREFIX + "/" if DEBUG_BUNDLE else None,
            })
        elif path == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /debug/\n",
                       "text/plain; charset=utf-8")
        elif DEBUG_BUNDLE and path in DIRS:
            if raw.endswith("/"):
                self._index(path)
            else:
                self._send(301, b"", "text/html", {"Location": raw + "/"})
        elif DEBUG_BUNDLE and path in BUNDLE:
            self._file(path, BUNDLE[path])
        else:
            self._json(404, {"error": "not_found"})

    def _index(self, url_dir):
        rows = []
        for name, rel in sorted(DIRS[url_dir].items()):
            try:
                st = (ROOT / rel).stat()
            except OSError:
                continue
            rows.append("%s%s%s%s" % (
                '<a href="%s">%s</a>' % (html.escape(name), html.escape(name)),
                " " * max(1, 51 - len(name)),
                time.strftime("%d-%b-%Y %H:%M", time.gmtime(st.st_mtime)),
                ("-" if name.endswith("/") else str(st.st_size)).rjust(20),
            ))
        title = html.escape(url_dir) + "/"
        body = ("<html>\n<head><title>Index of %s</title></head>\n<body>\n"
                "<h1>Index of %s</h1><hr><pre><a href=\"../\">../</a>\n%s\n"
                "</pre><hr></body>\n</html>\n"
                % (title, title, "\n".join(rows))).encode()
        self._audit(url_dir + "/", len(body))
        self._send(200, body, "text/html")

    def log_message(self, fmt, *a):
        sys.stderr.write("[http] %s %s\n" % (self.client_address[0], fmt % a))
        sys.stderr.flush()


def main():
    srv = ThreadingHTTPServer((BIND, PORT), VaultkeeperHandler)
    sys.stderr.write(
        "[http] vaultkeeper sync status on %s:%d (root=%s, debug_bundle=%s, decryptors=%s)\n"
        % (BIND, PORT, ROOT, "on" if DEBUG_BUNDLE else "off", ",".join(DECRYPTORS))
    )
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""A Trust Content Resolver stand-in over a real trust list: the shape of the TCR's resolve API,
with the content read live from a TSPA, so that the gateway's resolver (internal/trainresolve) can
be proven against what the publisher and the reconciler really wrote.

What it copies from upstream's resolver (train-trusted-content-resolver, openapi/tcr_openapi.yaml
and ResolutionService at commit e27b1ed): POST /tcr/v1/resolve with {issuer, trustSchemePointers};
each pointer resolved through DNS, the PTR record at _scheme._trust.<pointer> naming the trust
framework, or taken from --pointer DOMAIN=FRAMEWORK; one DID per framework (did:web:<framework>);
one endpoint per DID with vcUri, tlUri, trustList and vcVerified, where trustList is the first
provider whose TSPServices.TSPService[].ServiceTypeIdentifier equals the issuer exactly, and is
omitted when none matches; the response keys trustSchemePointers[].{pointer,dids,error} and
resolvedResults[].{did,resolvedDoc:{endpoints,didVerified},error}; a malformed body is 400; GET
/actuator/health answers. The list and its credential are fetched from
<tspa>/tspa/v1/<framework>/trust-list and <tspa>/tspa/v1/<framework>/vc/trust-list (one retry on a
failure); a list that cannot be read gives an endpoint with vcVerified false and no trustList.

What it does not do, on purpose: resolve DIDs, read DID documents or did-configuration, verify the
credential's signature or the list's hash (vcVerified is true when the list was read, false with
--vc-unverified), validate DNSSEC. didVerified is always false. Those are the real TCR's, and the
items the client's instance still needs are listed in scripts/train-resolve/README.md.

  fake_tcr.py --port PORT --tspa URL [--pointer DOMAIN=FRAMEWORK]... [--dns-server HOST [--dns-port N] [--dns-tcp]]
              [--vc-unverified] [--fail STATUS] [--log FILE]

Binds 127.0.0.1 only. Every request is appended as a JSON line to --log.
"""
import argparse, json, subprocess, sys, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PREFIX = "_scheme._trust."
LOG_LOCK = threading.Lock()   # handler threads append whole lines, one at a time


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--tspa", required=True, help="base URL of the TSPA up to its context path, e.g. http://127.0.0.1:16003/tspa-service")
    ap.add_argument("--pointer", action="append", default=[], metavar="DOMAIN=FRAMEWORK", help="static pointer resolution, instead of DNS")
    ap.add_argument("--dns-server", help="name server dig asks for the PTR record of a pointer")
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--dns-tcp", action="store_true", help="ask over TCP (a port-forward carries TCP only)")
    ap.add_argument("--vc-unverified", action="store_true", help="answer vcVerified false for every endpoint (a resolver that could not verify the credential)")
    ap.add_argument("--fail", type=int, metavar="STATUS", help="answer every resolve request with this status (an outage)")
    ap.add_argument("--log", help="append every request as a JSON line to this file")
    args = ap.parse_args()
    static = {}
    for p in args.pointer:
        if "=" not in p:
            ap.error(f"--pointer needs DOMAIN=FRAMEWORK, got {p!r}")
        d, fw = p.split("=", 1)
        static[d.rstrip(".")] = fw.rstrip(".")
    Handler.args, Handler.static = args, static
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def dig_ptr(args, pointer):
    """The frameworks the pointer claims: the PTR targets of _scheme._trust.<pointer>, prefix stripped."""
    name = pointer if pointer.startswith(PREFIX) else PREFIX + pointer
    cmd = ["dig", "+short", "+time=2", "+tries=1", f"-p{args.dns_port}", f"@{args.dns_server}", "PTR", name.rstrip(".") + "."]
    if args.dns_tcp:
        cmd.insert(1, "+tcp")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    fws = []
    for line in out.splitlines():
        t = line.strip().rstrip(".")
        if t.startswith(PREFIX):
            fws.append(t[len(PREFIX):])
    return fws


def fetch(url, timeout=5):
    """GET url as JSON, one retry: (doc, None) or (None, error text)."""
    last = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as r:
                return json.loads(r.read().decode()), None
        except urllib.error.HTTPError as e:
            last = f"{url}: {e.code}"
            if 400 <= e.code < 500:
                break           # a 404 does not get better on retry
        except (urllib.error.URLError, OSError, ValueError) as e:
            last = f"{url}: {e}"
        if attempt == 0:
            time.sleep(0.2)
    return None, last


def provider_for(doc, issuer):
    """The first provider with a service whose ServiceTypeIdentifier equals the issuer, as the TCR's
    findIssuerProvider does (exact string equality, first match)."""
    try:
        providers = doc["TrustServiceStatusList"]["TrustServiceProviderList"]["TrustServiceProvider"] or []
    except (KeyError, TypeError):
        return None
    for tsp in providers:
        services = ((tsp.get("TSPServices") or {}).get("TSPService") or [])
        if any(s.get("ServiceTypeIdentifier") == issuer for s in services):
            return tsp
    return None


class Handler(BaseHTTPRequestHandler):
    args = None
    static = {}

    def log_message(self, *_):   # quiet; the JSON log is the record
        pass

    def _log(self, status, body):
        if self.args.log:
            line = json.dumps({"ts": time.time(), "method": self.command, "path": self.path, "status": status, "body": body}) + "\n"
            with LOG_LOCK, open(self.args.log, "a", encoding="utf-8") as f:
                f.write(line)

    def _end(self, status, doc):
        raw = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/actuator/health":
            self._log(200, None)
            return self._end(200, {"status": "UP"})
        self._log(404, None)
        self._end(404, {"message": "not found"})

    def do_POST(self):
        if self.path != "/tcr/v1/resolve":
            self._log(404, None)
            return self._end(404, {"message": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw.decode())
            issuer, pointers = body["issuer"], body["trustSchemePointers"]
            if not isinstance(issuer, str) or not isinstance(pointers, list):
                raise ValueError("types")
        except (ValueError, KeyError, TypeError):
            self._log(400, raw.decode(errors="replace"))
            return self._end(400, {"message": "issuer and trustSchemePointers are required"})
        if self.args.fail:
            self._log(self.args.fail, body)
            return self._end(self.args.fail, {"message": "induced failure"})
        self._log(200, body)
        self._end(200, self.resolve(issuer, pointers))

    def resolve(self, issuer, pointers):
        resolved_pointers, results, seen = [], [], set()
        for p in pointers:
            p = str(p).rstrip(".")
            if p in self.static:
                fws = [self.static[p]]
            elif self.args.dns_server:
                fws = dig_ptr(self.args, p)
            else:
                fws = []
            if not fws:
                resolved_pointers.append({"pointer": p, "error": {"code": "dns_error", "message": f"no PTR record at {PREFIX}{p}"}})
                continue
            dids = [f"did:web:{fw}" for fw in fws]
            resolved_pointers.append({"pointer": p, "dids": dids})
            for fw, did in zip(fws, dids):
                if did in seen:
                    continue
                seen.add(did)
                results.append(self.result(fw, did, issuer))
        return {"trustSchemePointers": resolved_pointers, "resolvedResults": results}

    def result(self, fw, did, issuer):
        api = self.args.tspa.rstrip("/") + "/tspa/v1/" + fw
        tl_uri, vc_uri = api + "/trust-list", api + "/vc/trust-list"
        doc, err = fetch(tl_uri)
        endpoint = {"vcUri": vc_uri, "tlUri": tl_uri, "vcVerified": False}
        if doc is None:
            endpoint["error"] = err
        else:
            vc, _ = fetch(vc_uri)
            endpoint["vcVerified"] = (vc is not None) and not self.args.vc_unverified
            tsp = provider_for(doc, issuer)
            if tsp is not None:
                endpoint["trustList"] = tsp
        return {"did": did, "resolvedDoc": {"document": {"id": did}, "endpoints": [endpoint], "didVerified": False}}


if __name__ == "__main__":
    sys.exit(main())

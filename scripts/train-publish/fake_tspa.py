#!/usr/bin/env python3
"""A TSPA stand-in for publish_test.sh: the write semantics of the real trust-list API, read from
its source and recorded in docs/tspa-publish-api.md, with a token endpoint beside it.

Behaviour copied on purpose: every entry is validated against the real entry schema (tsp-schema.json,
upstream's TSPSchema.json, which carries only types and required fields) and refused with 400 and
the first messages otherwise; PUT .../tsp is create-only (400 when the UUID exists, 404 when the
list does not); PATCH .../tsp/{uuid} replaces and needs the body's UUID to equal the URL's; GETs
are public; a write without a usable token is answered 200 with an empty body and stores nothing
(the upstream quirk); a malformed token is 401; a token whose realm roles lack enrolltf is 403.

Tokens the token endpoint hands out, by client id: `publisher` with the secret in FAKE_TSPA_SECRET
gets a token with enrolltf; `weak` gets a token without it; `ghost` gets a token the write side
ignores as if absent. Anything else is 401. Three hooks exist for the test alone: POST /__fake/duplicate clones an
entry, POST /__fake/after-next-get removes or adds an entry right after the next GET (a writer racing
the publisher), and a framework named error-500* answers 500. State lives in memory; every request is
appended as a JSON line to --log.

  fake_tspa.py --port PORT [--log FILE]
"""
import argparse, hashlib, json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

CTX = "/tspa-service"
API = CTX + "/tspa/v1"
TOKEN_PATH = "/realms/test/protocol/openid-connect/token"
SECRET = os.environ.get("FAKE_TSPA_SECRET", "s3cret-for-tests")
TOKENS = {"enrolltf-token": "enrolltf", "plain-token": "none", "ghost-token": "ghost"}

SCHEMA = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "tsp-schema.json"), encoding="utf-8"))
TYPES = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float), "boolean": bool}


def schema_errors(node, data, at="$", out=None):
    """The draft-04 keywords the entry schema uses, and only those: $ref into definitions, anyOf, type,
    properties, required, items as one schema or as a tuple (description is ignored)."""
    out = [] if out is None else out
    if "$ref" in node:
        target = SCHEMA
        for k in node["$ref"].split("/")[1:]:   # "#/definitions/Name" -> definitions, Name
            target = target[k]
        return schema_errors(target, data, at, out)
    if "anyOf" in node:
        branches = [schema_errors(b, data, at, []) for b in node["anyOf"]]
        if not any(len(b) == 0 for b in branches):
            out.extend(min(branches, key=len))
        return out
    want = node.get("type")
    if want and not isinstance(data, TYPES[want]) or (want == "integer" and isinstance(data, bool)):
        out.append(f"{at}: expected {want}")
        return out
    if isinstance(data, dict):
        for k in node.get("required", []):
            if k not in data:
                out.append(f"{at}.{k}: required property missing")
        for k, sub in node.get("properties", {}).items():
            if k in data:
                schema_errors(sub, data[k], f"{at}.{k}", out)
    if isinstance(data, list) and "items" in node:
        items = node["items"]
        for i, v in enumerate(data):
            sub = items[i] if isinstance(items, list) and i < len(items) else (items if isinstance(items, dict) else None)
            if sub:
                schema_errors(sub, v, f"{at}[{i}]", out)
    return out


pending_after_get = []   # test hook: list mutations applied right after the next GET of a trust list
lists = {}      # framework -> {"FrameworkInformation": {...}, "TrustServiceProviderList": {"TrustServiceProvider": [...]}}
log_path = None


def log(rec):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


class Handler(BaseHTTPRequestHandler):
    server_version = "fake-tspa/1"

    def log_message(self, *a):  # quiet
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        if body:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode())

    def _auth(self):
        """None when no Authorization or a ghost token (the quirk), 'bad' when malformed, else the role."""
        h = self.headers.get("Authorization")
        if not h:
            return None
        if not h.startswith("Bearer "):
            return "bad"
        role = TOKENS.get(h[7:].strip())
        if role is None:
            return "bad"
        if role == "ghost":
            return None
        return role

    def _record(self, code):
        log({"ts": time.time(), "method": self.command, "path": self.path,
             "auth": "present" if self.headers.get("Authorization") else "absent", "status": code})

    def _list_doc(self, fw):
        return {"TrustServiceStatusList": lists[fw]}

    # ---- token endpoint, and two test hooks the API alone cannot produce -------------------
    def do_POST(self):
        if self.path == "/__fake/after-next-get":     # a writer racing the publisher between its read and its write
            req = json.loads(self._body())
            pending_after_get.append(req)
            return self._end(200, {"pending": len(pending_after_get)})
        if self.path == "/__fake/duplicate":          # clone one entry: the duplicate-entry outcome
            req = json.loads(self._body())
            entries = lists[req["framework"]]["TrustServiceProviderList"]["TrustServiceProvider"]
            entries.extend([json.loads(json.dumps(e)) for e in entries if e["UUID"] == req["uuid"]])
            return self._end(200, {"entries": len(entries)})
        if self.path == TOKEN_PATH:
            form = parse_qs(self._body().decode())
            cid = form.get("client_id", [""])[0]
            sec = form.get("client_secret", [""])[0]
            if form.get("grant_type", [""])[0] != "client_credentials":
                return self._end(400, {"error": "unsupported_grant_type"})
            if cid == "publisher" and sec == SECRET:
                return self._end(200, {"access_token": "enrolltf-token", "token_type": "Bearer", "expires_in": 300})
            if cid == "weak":
                return self._end(200, {"access_token": "plain-token", "token_type": "Bearer", "expires_in": 300})
            if cid == "ghost":
                return self._end(200, {"access_token": "ghost-token", "token_type": "Bearer", "expires_in": 300})
            return self._end(401, {"error": "invalid_client"})
        self._end(404, {"message": "not found"})

    def _end(self, code, obj=None, empty=False):
        self._record(code)
        if empty or obj is None:
            self._send(code)
        else:
            self._json(code, obj)

    # ---- reads (public) --------------------------------------------------------------------
    def do_GET(self):
        p = self.path
        if p == CTX + "/actuator/health":
            return self._end(200, {"status": "UP"})
        if p.startswith(API + "/") and p.endswith("/trust-list"):
            fw = p[len(API) + 1:-len("/trust-list")]
            if fw.startswith("error-500"):           # a broken TSPA: the tspa-error outcome
                return self._end(500, {"message": "internal error", "status": 500})
            if fw.endswith("/vc"):
                fw = fw[:-3]
                if fw not in lists:
                    return self._end(404, {"message": "Trustlist not found", "status": 404})
                raw = json.dumps(self._list_doc(fw), sort_keys=True).encode()
                vc = {"type": ["VerifiableCredential"], "issuer": "did:example:fake-tspa",
                      "credentialSubject": {"trustlisttype": "JSON based Trust-lists",
                                            "trustlistURI": f"{API}/{fw}/trust-list",
                                            "hash": hashlib.sha256(raw).hexdigest()}}
                return self._end(200, vc)
            if fw not in lists:
                return self._end(404, {"message": "Trustlist not found", "status": 404})
            doc = json.loads(json.dumps(self._list_doc(fw)))
            self._end(200, doc)
            while pending_after_get:               # the racing writer acts once the publisher has read
                req = pending_after_get.pop(0)
                entries = lists[req["framework"]].setdefault("TrustServiceProviderList", {"TrustServiceProvider": []})["TrustServiceProvider"]
                if "remove" in req:
                    entries[:] = [e for e in entries if e["UUID"] != req["remove"]]
                if "add" in req:
                    entries.append(req["add"])
            return
        self._end(404, {"message": "not found"})

    # ---- writes (enrolltf) -----------------------------------------------------------------
    def _gate(self):
        """True when the write may run; otherwise the response has been sent."""
        a = self._auth()
        if a is None:            # the quirk: the controller never runs, 200 and nothing happens
            self._end(200, empty=True)
            return False
        if a == "bad":
            self._end(401, {"error": "An error occurred while attempting to decode the Jwt: Malformed token", "status": 401})
            return False
        if a != "enrolltf":
            self._end(403, empty=True)
            return False
        return True

    def do_PUT(self):
        p = self.path
        if p.startswith(API + "/init/json/") and p.endswith("/trust-list"):
            if not self._gate():
                return
            fw = p[len(API + "/init/json/"):-len("/trust-list")]
            if fw in lists:
                return self._end(400, {"message": "Trustlist is already Existing", "status": 400})
            body = json.loads(self._body() or b"{}")
            lists[fw] = {"FrameworkInformation": body.get("TrustServiceStatusList", {}).get("FrameworkInformation", {})}
            return self._end(201, {"MapN": {"message": f"Trustlist created for {fw}.", "status": 201}})
        if p.startswith(API + "/") and p.endswith("/trust-list/tsp"):
            if not self._gate():
                return
            fw = p[len(API) + 1:-len("/trust-list/tsp")]
            if fw not in lists:
                return self._end(404, {"message": "Trustlist not found", "status": 404})
            body = json.loads(self._body() or b"{}")
            errs = schema_errors(SCHEMA, body)
            if errs:
                return self._end(400, {"message": "schema validation failed: " + "; ".join(errs[:5]), "status": 400})
            tsp = body["TrustServiceProvider"]
            entries = lists[fw].setdefault("TrustServiceProviderList", {"TrustServiceProvider": []})["TrustServiceProvider"]
            if any(e["UUID"] == tsp["UUID"] for e in entries):
                return self._end(400, {"message": f"TSP with UUID {tsp['UUID']} already exists", "status": 400})
            entries.append(tsp)
            return self._end(201, {"MapN": {"message": f"TSP published for {fw}.", "status": 201}})
        self._end(404, {"message": "not found"})

    def do_PATCH(self):
        p = self.path
        marker = "/trust-list/tsp/"
        if p.startswith(API + "/") and marker in p:
            if not self._gate():
                return
            fw, uid = p[len(API) + 1:].split(marker, 1)
            if fw not in lists:
                return self._end(404, {"message": "Trustlist not found", "status": 404})
            body = json.loads(self._body() or b"{}")
            errs = schema_errors(SCHEMA, body)
            if errs:
                return self._end(400, {"message": "schema validation failed: " + "; ".join(errs[:5]), "status": 400})
            tsp = body["TrustServiceProvider"]
            if tsp.get("UUID") != uid:
                return self._end(400, {"message": "UUID in URL and body do not match", "status": 400})
            entries = lists[fw].get("TrustServiceProviderList", {}).get("TrustServiceProvider", [])
            for i, e in enumerate(entries):
                if e["UUID"] == uid:
                    entries[i] = tsp
                    return self._end(200, {"MapN": {"message": f"TSP update for {fw} with UUID :{uid}", "status": 200}})
            return self._end(404, {"message": f"TSP {uid} not found", "status": 404})
        self._end(404, {"message": "not found"})

    def do_DELETE(self):
        p = self.path
        marker = "/trust-list/tsp/"
        if p.startswith(API + "/") and marker in p:
            if not self._gate():
                return
            fw, uid = p[len(API) + 1:].split(marker, 1)
            entries = lists.get(fw, {}).get("TrustServiceProviderList", {}).get("TrustServiceProvider", [])
            lists.get(fw, {}).get("TrustServiceProviderList", {})["TrustServiceProvider"] = [e for e in entries if e["UUID"] != uid]
            return self._end(200, {"MapN": {"message": "TSP deleted", "status": 200}})
        if p.startswith(API + "/") and p.endswith("/trust-list"):
            if not self._gate():
                return
            lists.pop(p[len(API) + 1:-len("/trust-list")], None)
            return self._end(200, {"MapN": {"message": "Trustlist deleted", "status": 200}})
        self._end(404, {"message": "not found"})


def main():
    global log_path
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--log")
    a = ap.parse_args()
    log_path = a.log
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"fake-tspa listening on 127.0.0.1:{a.port}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

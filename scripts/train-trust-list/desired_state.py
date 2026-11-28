#!/usr/bin/env python3
"""The desired state of a TRAIN trust list, as reconcile.sh needs it: validated, rendered into the
TSPA's entries, and compared with the list as it is.

  desired_state.py validate FILE                 exit 0 when FILE satisfies the contract and its own rules
  desired_state.py render FILE                   the entries FILE describes, with their UUIDs, as JSON
  desired_state.py plan FILE LIVE_LIST [TEMPLATE]  what apply would write, given the list read from the TSPA
  desired_state.py diff OLD NEW                  the change from OLD to NEW, in words (for a pull request)

The contract is docs/contracts/train-trust-list.v1.schema.json; the keywords it uses are checked
here, and only those, so the check needs nothing beyond the standard library. On top of the schema:
issuer ids and lookup keys are unique in the file, and an issuer's zone names a declared zone.

An entry's UUID is a UUID v5 of the framework and the issuer id, the same on every run, so the
first write is a PUT and every later one a PATCH of that entry. Every entry the reconciler writes
carries {Type: managed-by, Value: train-trust-list/<framework>} in its identifier list: that marker
is what lets the reconciler remove an entry whose issuer left the file, and what keeps it away
from every other entry in the list (the pipeline's measurement entries, the client's own).
"""
import json
import os
import re
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SCHEMA_PATH = os.path.join(ROOT, "docs", "contracts", "train-trust-list.v1.schema.json")
TEMPLATE_PATH = os.path.join(HERE, "entry.tmpl.json")
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/eclipse-xfsc/facis-zero-trust-demonstrator/train-trust-list")
MARKER_TYPE = "managed-by"
TYPES = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float), "boolean": bool}


def fail(code, msg):
    print(f"desired-state: {msg}", file=sys.stderr)
    sys.exit(code)


# ---- the contract ------------------------------------------------------------------------------
def matches(pattern, data):
    """JSON Schema patterns are ECMA regexes where $ is the end of the string; Python's $ also matches
    before a trailing newline, so an anchored pattern is applied with fullmatch."""
    if pattern.startswith("^") and pattern.endswith("$"):
        return re.fullmatch(pattern[1:-1], data) is not None
    return re.search(pattern, data) is not None


def schema_errors(node, data, at="$", out=None):
    """The keywords the contract uses: type, const, enum, required, properties, additionalProperties,
    pattern, minLength, maxLength, minItems, uniqueItems, items, format (uri)."""
    out = [] if out is None else out
    if "const" in node and json.dumps(data, sort_keys=True) != json.dumps(node["const"], sort_keys=True):
        out.append(f"{at}: must be {json.dumps(node['const'])}")
        return out
    if "enum" in node and data not in node["enum"]:
        out.append(f"{at}: must be one of {json.dumps(node['enum'])}")
        return out
    want = node.get("type")
    if want:
        ok = isinstance(data, TYPES[want]) and not (want in ("integer", "number") and isinstance(data, bool))
        if not ok:
            out.append(f"{at}: expected {want}")
            return out
    if isinstance(data, str):
        if "pattern" in node and not matches(node["pattern"], data):
            out.append(f"{at}: does not match {node['pattern']}")
        if "minLength" in node and len(data) < node["minLength"]:
            out.append(f"{at}: shorter than {node['minLength']}")
        if "maxLength" in node and len(data) > node["maxLength"]:
            out.append(f"{at}: longer than {node['maxLength']}")
        if node.get("format") == "uri" and not re.match(r"^[a-z][a-z0-9+.-]*://\S+$", data):
            out.append(f"{at}: not a URI")
    if isinstance(data, dict):
        for k in node.get("required", []):
            if k not in data:
                out.append(f"{at}.{k}: required property missing")
        props = node.get("properties", {})
        for k, v in data.items():
            if k in props:
                schema_errors(props[k], v, f"{at}.{k}", out)
            elif node.get("additionalProperties") is False:
                out.append(f"{at}.{k}: unknown property")
    if isinstance(data, list):
        if "minItems" in node and len(data) < node["minItems"]:
            out.append(f"{at}: fewer than {node['minItems']} items")
        if node.get("uniqueItems"):
            seen = [json.dumps(x, sort_keys=True) for x in data]
            if len(set(seen)) != len(seen):
                out.append(f"{at}: items are not unique")
        if "items" in node:
            for i, v in enumerate(data):
                schema_errors(node["items"], v, f"{at}[{i}]", out)
    return out


def load_desired(path):
    try:
        with open(path, encoding="utf-8") as f:
            desired = json.load(f)
    except (OSError, ValueError) as e:
        fail(2, f"cannot read {path}: {e}")
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    errs = schema_errors(schema, desired)
    if errs:
        fail(2, f"{path} does not satisfy the contract: " + "; ".join(errs[:8]))
    ids = [i["id"] for i in desired["issuers"]]
    if len(set(ids)) != len(ids):
        fail(2, f"{path}: issuer ids are not unique")
    stis = [i["serviceTypeIdentifier"] for i in desired["issuers"]]
    if len(set(stis)) != len(stis):
        fail(2, f"{path}: two issuers share a serviceTypeIdentifier; the TCR could not tell them apart")
    zones = [z["name"] for z in desired.get("zones", [])]
    if len(set(zones)) != len(zones):
        fail(2, f"{path}: zone names are not unique")
    domains = [z["domain"] for z in desired.get("zones", [])]
    if len(set(domains)) != len(domains):
        fail(2, f"{path}: zone domains are not unique")
    for i in desired["issuers"]:
        if "zone" in i and i["zone"] not in zones:
            fail(2, f"{path}: issuer {i['id']} names zone {i['zone']}, which the file does not declare")
    return desired


# ---- the entries -------------------------------------------------------------------------------
def marker(framework):
    return {"Type": MARKER_TYPE, "Value": f"train-trust-list/{framework}"}


def entry_uuid(framework, issuer_id):
    return str(uuid.uuid5(NAMESPACE, f"{framework}/{issuer_id}"))


def render_entry(desired, issuer, template):
    fw = desired["framework"]
    tsp = json.loads(json.dumps(template["TrustServiceProvider"]))
    tsp["UUID"] = entry_uuid(fw, issuer["id"])
    tsp["TSPName"] = issuer["name"]
    tsp["TSPTradeName"] = issuer["id"]
    info = tsp["TSPInformation"]
    info["TSPInformationURI"] = issuer.get("informationUri", "n/a")
    info["TSPCertificationList"]["TSPCertification"] = []
    idents = [marker(fw), {"Type": "issuer", "Value": issuer["id"]}]
    if "zone" in issuer:
        idents.append({"Type": "zone", "Value": issuer["zone"]})
    info["TSPEntityIdentifierList"]["TSPEntityIdendifier"] = idents
    svc = tsp["TSPServices"]["TSPService"][0]
    svc["ServiceName"] = issuer.get("serviceName", "credential-issuer")
    svc["ServiceTypeIdentifier"] = issuer["serviceTypeIdentifier"]
    svc["ServiceCurrentStatus"] = issuer.get("status", "active")
    svc["StatusStartingTime"] = ""   # the reconciler keeps the live entry's, or sets the time of the first write
    svc["ServiceDigitalIdentity"]["DigitalId"]["DID"] = issuer.get("did", issuer["serviceTypeIdentifier"])
    add = svc["AdditionalServiceInformation"]
    add["ServiceIssuedCredentialTypes"]["CredentialType"] = [{"Type": t} for t in issuer.get("credentialTypes", ["n/a"])]
    add["ServiceSupplyPoint"] = issuer.get("supplyPoint", "n/a")
    return {"TrustServiceProvider": tsp}


def render(desired, template_path):
    with open(template_path, encoding="utf-8") as f:
        template = json.load(f)
    return {
        "framework": desired["framework"],
        "marker": marker(desired["framework"]),
        "zones": [z["domain"] for z in desired.get("zones", [])],
        "issuers": [
            {"id": i["id"], "uuid": entry_uuid(desired["framework"], i["id"]),
             "serviceTypeIdentifier": i["serviceTypeIdentifier"], "entry": render_entry(desired, i, template)}
            for i in desired["issuers"]
        ],
    }


# ---- the plan ----------------------------------------------------------------------------------
def live_entries(live):
    return (live.get("TrustServiceStatusList", {}).get("TrustServiceProviderList") or {}).get("TrustServiceProvider") or []


def is_managed(entry, mark):
    idents = ((entry.get("TSPInformation") or {}).get("TSPEntityIdentifierList") or {}).get("TSPEntityIdendifier") or []
    return any(isinstance(p, dict) and p.get("Type") == mark["Type"] and p.get("Value") == mark["Value"] for p in idents)


def sti_of(entry):
    svcs = ((entry.get("TSPServices") or {}).get("TSPService")) or []
    return svcs[0].get("ServiceTypeIdentifier") if svcs and isinstance(svcs[0], dict) else None


def start_of(entry):
    svcs = ((entry.get("TSPServices") or {}).get("TSPService")) or []
    return svcs[0].get("StatusStartingTime") if svcs and isinstance(svcs[0], dict) else None


def canonical(tsp):
    return json.dumps(tsp, sort_keys=True, separators=(",", ":"))


def plan(desired, live, template_path, now):
    """create, replace, delete, unchanged, conflict and unowned, with the request body of every
    write. The body of a replace keeps the live entry's StatusStartingTime, so a change of text is
    not a new start; a create sets it to now. Deletes come first when applied: an issuer that took
    over a lookup key under a new id is created only once the old entry is gone."""
    rendered = render(desired, template_path)
    mark = rendered["marker"]
    by_uuid = {}
    for e in live_entries(live):
        by_uuid.setdefault(e.get("UUID"), []).append(e)
    desired_uuids = {i["uuid"] for i in rendered["issuers"]}
    out = {"framework": rendered["framework"], "zones": rendered["zones"], "create": [], "replace": [],
           "delete": [], "unchanged": [], "conflict": [], "duplicate": [], "unowned": []}
    # Entries this file owns whose issuer left it: deleted first, so a lookup key they hold is free
    # for an issuer that took it over under another id (a rename is a removal and a creation).
    leaving = {e.get("UUID") for e in live_entries(live) if is_managed(e, mark) and e.get("UUID") not in desired_uuids}
    for uid, es in by_uuid.items():
        if len(es) > 1 and (uid in desired_uuids or any(is_managed(e, mark) for e in es)):
            out["duplicate"].append({"uuid": uid, "count": len(es)})
    for i in rendered["issuers"]:
        # Another live entry under the same lookup key: the TCR returns one of them, which one is
        # not defined. A file that names it is wrong, whatever that other entry is.
        others = [e for e in live_entries(live) if sti_of(e) == i["serviceTypeIdentifier"]
                  and e.get("UUID") != i["uuid"] and e.get("UUID") not in leaving]
        if others:
            out["conflict"].append({"id": i["id"], "serviceTypeIdentifier": i["serviceTypeIdentifier"],
                                    "uuids": [e.get("UUID") for e in others],
                                    "managed": [is_managed(e, mark) for e in others]})
            continue
        tsp = i["entry"]["TrustServiceProvider"]
        live_e = by_uuid.get(i["uuid"], [None])[0]
        if live_e is None:
            tsp["TSPServices"]["TSPService"][0]["StatusStartingTime"] = now
            out["create"].append({"id": i["id"], "uuid": i["uuid"], "serviceTypeIdentifier": i["serviceTypeIdentifier"],
                                  "body": {"TrustServiceProvider": tsp}})
            continue
        if not is_managed(live_e, mark):
            # An entry under this file's UUID that does not carry its marker is not its to rewrite:
            # someone took it over, or another writer derived the same UUID. Refused, never replaced.
            out["unowned"].append({"id": i["id"], "uuid": i["uuid"], "name": live_e.get("TSPName")})
            continue
        tsp["TSPServices"]["TSPService"][0]["StatusStartingTime"] = start_of(live_e) or now
        if canonical(tsp) == canonical(live_e):
            out["unchanged"].append({"id": i["id"], "uuid": i["uuid"]})
        else:
            out["replace"].append({"id": i["id"], "uuid": i["uuid"], "serviceTypeIdentifier": i["serviceTypeIdentifier"],
                                   "body": {"TrustServiceProvider": tsp}})
    for e in live_entries(live):
        if e.get("UUID") in leaving:
            out["delete"].append({"uuid": e.get("UUID"), "serviceTypeIdentifier": sti_of(e), "name": e.get("TSPName")})
    out["converged"] = not (out["create"] or out["replace"] or out["delete"] or out["conflict"] or out["duplicate"] or out["unowned"])
    return out


# ---- the change, in words ----------------------------------------------------------------------
def diff(old, new):
    lines = []
    if old["framework"] != new["framework"]:
        lines.append(f"! framework renamed from {old['framework']} to {new['framework']}: every entry of the old framework stays where it is; the new framework's list must exist")
    oz = {z["domain"] for z in old.get("zones", [])}
    nz = {z["domain"] for z in new.get("zones", [])}
    for d in sorted(nz - oz):
        lines.append(f"+ zone {d} claims the framework")
    for d in sorted(oz - nz):
        lines.append(f"- zone {d} no longer claims the framework (the PTR record is not removed by apply; see the page)")
    oi = {i["id"]: i for i in old["issuers"]}
    ni = {i["id"]: i for i in new["issuers"]}
    for k in sorted(set(ni) - set(oi)):
        lines.append(f"+ issuer {k} ({ni[k]['serviceTypeIdentifier']}): a new entry; verifiers trust it once their copy of the list refreshes")
    for k in sorted(set(oi) - set(ni)):
        lines.append(f"- issuer {k} ({oi[k]['serviceTypeIdentifier']}): its entry is removed; a verifier that cached the list keeps trusting it until the window closes")
    for k in sorted(set(oi) & set(ni)):
        if oi[k] == ni[k]:
            continue
        changed = sorted(f for f in set(oi[k]) | set(ni[k]) if oi[k].get(f) != ni[k].get(f))
        if "serviceTypeIdentifier" in changed:
            lines.append(f"~ issuer {k}: lookup key {oi[k]['serviceTypeIdentifier']} -> {ni[k]['serviceTypeIdentifier']}; verifiers asking for the old key stop finding the entry")
            changed.remove("serviceTypeIdentifier")
        if changed:
            lines.append(f"~ issuer {k}: {', '.join(changed)} changed")
    return lines or ["= no change to what the framework trusts"]


def main(argv):
    if len(argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "validate" and len(argv) == 3:
        load_desired(argv[2])
        print("ok")
        return 0
    if cmd == "render" and len(argv) == 3:
        print(json.dumps(render(load_desired(argv[2]), TEMPLATE_PATH), indent=2))
        return 0
    if cmd == "plan" and len(argv) in (4, 5):
        desired = load_desired(argv[2])
        try:
            with open(argv[3], encoding="utf-8") as f:
                live = json.load(f)
        except (OSError, ValueError) as e:
            fail(1, f"cannot read the live list {argv[3]}: {e}")
        now = os.environ.get("TRAIN_TRUST_LIST_NOW") or __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(json.dumps(plan(desired, live, argv[4] if len(argv) == 5 else TEMPLATE_PATH, now)))
        return 0
    if cmd == "diff" and len(argv) == 4:
        print("\n".join(diff(load_desired(argv[2]), load_desired(argv[3]))))
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

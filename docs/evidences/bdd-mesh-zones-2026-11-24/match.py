#!/usr/bin/env python3
"""match.py MATRIX_CSV DENIAL_LINES YEAR: pair each plain-text probe of a plane-separation run with
the denial line its destination's proxy wrote.

MATRIX_CSV is the verifier's matrix.csv. DENIAL_LINES holds one "<namespace>/<pod> <json>" line per
filter_chain_not_found line read from the proxies of the plane namespaces while the run went on. A
probe and a line pair when the pod is the probe's destination, the line is a refused connection
without an identity (detail filter_chain_not_found, flag NR, no source), and its time is within one
second of the date and time Hubble gives for the forwarded request (Hubble prints no year: YEAR is
the run's). A probe with two such lines within the second is not paired.
Exit status 1 when there is no plain-text probe, or one the verifier did not pass, or one without
its line.
"""
import csv, datetime, json, re, sys


def main(matrix, denials, year):
    probes = [r for r in csv.DictReader(open(matrix)) if r["probe"].startswith("plain text")]
    lines = []
    for raw in open(denials):
        if not raw.strip():
            continue
        pod, rest = raw.split(" ", 1)
        line = json.loads(rest)
        if line.get("detail") == "filter_chain_not_found" and line.get("flags") == "NR" and not line.get("source"):
            when = datetime.datetime.strptime(line["time"], "%Y-%m-%dT%H:%M:%S.%fZ")
            lines.append((pod, when, line))
    used, paired, failed = set(), 0, 0
    print("from | destination | port | kind | verifier | forwarded (Hubble) | denial line of the destination's proxy")
    for p in probes:
        failed += p["verdict"] != "pass"
        seen = re.search(r"Hubble: (\w+ \d+) ([0-9:.]+):", p["evidence"])
        near = []
        if seen:
            for i, (pod, when, _) in enumerate(lines):
                at = datetime.datetime.strptime("%s %s %s" % (int(year), seen.group(1), seen.group(2)), "%Y %b %d %H:%M:%S.%f")
                if i not in used and pod == p["destination"] and abs((when - at).total_seconds()) < 1:
                    near.append(i)
        shown = "none" if not near else "ambiguous: %d lines within the second" % len(near)
        if len(near) == 1:
            used.add(near[0])
            paired += 1
            line = lines[near[0]][2]
            shown = "%s detail=%s flags=%s source=%s" % (line["time"], line["detail"], line["flags"], line["source"])
        print(" | ".join([p["namespace"] + "/" + p["caller"], p["destination"], p["port"], p["kind"], p["verdict"],
                          "%s %s" % seen.groups() if seen else "none", shown]))
    spare = [lines[i] for i in range(len(lines)) if i not in used]
    for pod, _, line in spare:
        print("line of no plain-text probe: %s %s" % (pod, line["time"]))
    print("%d plain-text probe(s), %d with the denial line; %d line(s) collected, %d of no plain-text probe"
          % (len(probes), paired, len(lines), len(spare)))
    return 0 if probes and not failed and paired == len(probes) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))

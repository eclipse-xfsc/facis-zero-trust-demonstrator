#!/usr/bin/env python3
"""Check scratch-image paths are accessible to the configured non-root user."""

import argparse
import json
import subprocess
import tarfile


def check(image, binary):
    config = json.loads(subprocess.check_output(
        ["docker", "image", "inspect", image], text=True))[0]["Config"]
    if config.get("User") != "65532:65532":
        raise ValueError("expected runtime user 65532:65532")
    paths = {
        "etc": (True, 1),
        "etc/ssl": (True, 1),
        "etc/ssl/certs": (True, 1),
        "etc/ssl/certs/ca-certificates.crt": (False, 4),
        "app": (True, 1),
        "app/" + binary: (False, 5),
    }
    container = subprocess.check_output(
        ["docker", "create", "--platform", "linux/amd64", image], text=True).strip()
    failures = []
    try:
        with subprocess.Popen(["docker", "export", container], stdout=subprocess.PIPE) as export:
            with tarfile.open(fileobj=export.stdout, mode="r|") as archive:
                for entry in archive:
                    name = entry.name.removeprefix("./").rstrip("/")
                    if name not in paths:
                        continue
                    directory, required = paths.pop(name)
                    shift = 6 if entry.uid == 65532 else 3 if entry.gid == 65532 else 0
                    allowed = (entry.mode >> shift) & 7
                    kind_ok = entry.isdir() if directory else entry.isfile()
                    if not kind_ok or allowed & required != required:
                        failures.append(f"/{name}: inaccessible (mode {entry.mode:04o})")
            if export.wait() != 0:
                raise RuntimeError("docker export failed")
        failures.extend(f"/{name}: missing" for name in paths)
        if failures:
            raise ValueError("; ".join(failures))
        print(f"PASS: {binary} runtime paths are accessible to UID 65532")
    finally:
        subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("binary", choices=("participant", "protected-resource"))
    args = parser.parse_args()
    try:
        check(args.image, args.binary)
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"FAIL: {error}\n")

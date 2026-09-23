#!/usr/bin/env bash
#
# Reads three proof.sh outputs from the environment -- HOST, CONTAINER, PERTURBED
# -- and decides whether the fixture measured the same everywhere for the right
# reason.
#
# Two assertions, and both have to hold:
#
#   1. the normalised measurement is identical on all three checkouts, which is
#      the property ZT-35 needs;
#   2. the perturbed checkout's raw measurement differs from the others', which is
#      what makes the first assertion mean something. Without it the job would
#      also pass on a workflow that normalised nothing and ran three identical
#      machines.
#
# The HOST and CONTAINER raw measurements are not required to differ or to agree.
# They are a different question -- whether the measuring environment matters --
# and the answer is reported rather than enforced.

set -euo pipefail

field() { # field NAME < proof output
  sed -n "s/^$1=\\([0-9a-f]*\\)$/\\1/p"
}

status=0
note() {
  printf '%s\n' "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}
fail() { note "FAIL  $1"; status=1; }

for name in HOST CONTAINER PERTURBED; do
  if [ -z "${!name:-}" ]; then
    echo "compare.sh: $name is empty; the measuring job did not report a result" >&2
    exit 1
  fi
done

note '### Measurement determinism'
note ''
note '| checkout | raw template hash | normalised template hash |'
note '| --- | --- | --- |'

declare -A normalised raw
for name in HOST CONTAINER PERTURBED; do
  raw[$name]=$(field raw_templateHash <<< "${!name}")
  normalised[$name]=$(field normalised_templateHash <<< "${!name}")
  if [ -z "${raw[$name]}" ] || [ -z "${normalised[$name]}" ]; then
    echo "compare.sh: $name carries no template hash" >&2
    exit 1
  fi
  note "| $name | \`${raw[$name]:0:16}…\` | \`${normalised[$name]:0:16}…\` |"
done
note ''

# 1. One measurement, three checkouts.
reference="${normalised[HOST]}"
for name in CONTAINER PERTURBED; do
  if [ "${normalised[$name]}" != "$reference" ]; then
    fail "$name normalised to ${normalised[$name]}, HOST to $reference"
  fi
done

# Every field, not only the template hash: a reference value that agreed on the
# template while disagreeing on its inputs would mean the hash had collided or
# the comparison was reading the wrong thing.
for f in configSha256 rootfsSha256; do
  ref=$(field "normalised_$f" <<< "$HOST")
  for name in CONTAINER PERTURBED; do
    got=$(field "normalised_$f" <<< "${!name}")
    [ "$got" = "$ref" ] || fail "$name normalised $f is $got, HOST is $ref"
  done
done

# 2. The normalisation is load-bearing.
if [ "${raw[PERTURBED]}" = "${raw[HOST]}" ]; then
  fail 'the perturbed checkout measured the same as HOST before normalisation;
        the control did not perturb anything, so this run proves nothing'
fi

if [ $status -eq 0 ]; then
  note "PASS  three checkouts, one normalised measurement: \`$reference\`"
  note ''
  note "The perturbed checkout measured \`${raw[PERTURBED]}\` before normalisation, so the"
  note 'agreement above is the normalisation and not a coincidence.'
fi

exit $status

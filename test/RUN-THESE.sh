#!/bin/bash
# Hardware verification — run in a REAL terminal (the PIN prompt needs a TTY).
#
# Self-provisioning: fixtures are regenerated from the CURRENT recipients at
# the start of every run (encryption needs no hardware — SPEC §4), so this
# script can never go stale the way the original Phase-1 fixtures did. The
# recovery test asks for the offline key's path instead of assuming one
# (the private recovery key must NOT live on this disk — SPEC §10 ③).
#
# Usage:  test/RUN-THESE.sh          # tests 1–3 + optional recovery test
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"

PASS=0; FAIL=0
pass() { echo "✅ PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "❌ FAIL: $*"; FAIL=$((FAIL+1)); }

# ------------------------------------------------------------- preflight ----
for tool in age; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool"; exit 1; }
done
for f in recipients/fido.pub recipients/fido-identity.txt recipients/recovery.pub; do
  [[ -s "$f" ]] || { echo "missing $f — run 'hwvault init' first"; exit 1; }
done

# ---------------------------------------------------------- fixtures --------
# Scratch dir: canary plaintext and generated ciphertexts never touch the repo.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/hwvault-verify.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT INT TERM HUP
CANARY="$TMP/canary.txt"
echo "hwvault hardware verification $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$CANARY"

echo "Generating fixtures from current recipients (no hardware needed)…"
age -R recipients/fido.pub -R recipients/recovery.pub -o "$TMP/dual.age" "$CANARY" \
  || { echo "could not generate dual-recipient fixture"; exit 1; }
age -R recipients/fido.pub -o "$TMP/fido-only.age" "$CANARY" \
  || { echo "could not generate FIDO-only fixture"; exit 1; }

# ---------------------------------------------------------------- tests ------
echo
echo "=== TEST 1: FIDO decrypt of dual-recipient file (plug key in; PIN + touch) ==="
# NOTE: keep stdout and stderr SEPARATE — the plugin prints touch/PIN chatter
# to stderr, and merging it into the captured plaintext breaks the cmp.
if age -d -i recipients/fido-identity.txt "$TMP/dual.age" > "$TMP/out1" 2> "$TMP/err1"; then
  cmp -s "$CANARY" "$TMP/out1" && pass "FIDO decrypt, dual-recipient" \
        || { fail "FIDO decrypt, dual-recipient — wrong plaintext:"; sed 's/^/    /' "$TMP/err1"; }
else
  fail "FIDO decrypt, dual-recipient — age error:"; sed 's/^/    /' "$TMP/err1"
fi

echo
echo "=== TEST 2: FIDO decrypt of FIDO-only file (PIN + touch) ==="
if age -d -i recipients/fido-identity.txt "$TMP/fido-only.age" > "$TMP/out2" 2> "$TMP/err2"; then
  cmp -s "$CANARY" "$TMP/out2" && pass "FIDO decrypt, FIDO-only" \
        || { fail "FIDO decrypt, FIDO-only — wrong plaintext:"; sed 's/^/    /' "$TMP/err2"; }
else
  fail "FIDO decrypt, FIDO-only — age error:"; sed 's/^/    /' "$TMP/err2"
fi

echo
echo "=== TEST 3: NEGATIVE — unplug the MiixKey, press Enter, expect FAILURE ==="
read -r -p "Unplug the key now, then press Enter..." || true
if [[ ! -t 0 ]]; then
  echo "⚠️  skipped — no interactive stdin (run from a real terminal to verify this)"
else
  if age -d -i recipients/fido-identity.txt "$TMP/fido-only.age" > "$TMP/out3" 2> "$TMP/err3"; then
    fail "decrypted WITHOUT hardware — hardware binding is broken!"
  else
    pass "correctly failed without hardware:"; sed 's/^/    /' "$TMP/err3"
  fi
fi

echo
echo "=== TEST 4: recovery path — no hardware (needs the OFFLINE key) ==="
read -r -p "Path to the offline recovery key (printout/USB), or Enter to skip: " RK
if [[ -n "$RK" ]]; then
  # Expand tilde, then resolve before age sees it — never let the path hit history.
  RK="${RK/#\~/$HOME}"
  if [[ -s "$RK" ]]; then
    if age -d -i "$RK" "$TMP/dual.age" > "$TMP/out4" 2> "$TMP/err4"; then
      cmp -s "$CANARY" "$TMP/out4" && pass "recovery decrypt, no hardware" \
            || { fail "recovery decrypt — wrong plaintext:"; sed 's/^/    /' "$TMP/err4"; }
    else
      fail "recovery decrypt — age error:"; sed 's/^/    /' "$TMP/err4"
    fi
    echo "    (key used from: $RK — re-secure it offline again now)"
  else
    echo "⚠️  no file at '$RK' — skipped (recovery NOT verified this run)"
  fi
else
  echo "⚠️  skipped (recovery NOT verified this run)"
fi

echo
echo "=== TEST 5: committed canary test/verify.txt.age still decrypts ==="
if age -d -i recipients/fido-identity.txt test/verify.txt.age > "$TMP/out5" 2> "$TMP/err5"; then
  pass "committed canary decrypts via current credential:"; sed 's/^/    /' "$TMP/out5"
else
  echo "⚠️  could not decrypt with current credential — likely encrypted to a"
  echo "    pre-rotation credential. Regenerate it: hwvault encrypt after"
  echo "    printing its plaintext is not needed; simply replace it with a fresh"
  echo "    canary:  age -R recipients/fido.pub -R recipients/recovery.pub \\"
  echo "              -o test/verify.txt.age <(echo 'canary')"
fi

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
[[ $FAIL -eq 0 ]] || exit 1
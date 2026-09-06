#!/usr/bin/env bash
# Test suite for hwvault.
#
# Runs fully unattended: every test here uses the BACKUP identity, which needs
# no hardware and no TTY. The FIDO paths (decrypt/edit/exec against the token)
# cannot be automated — they require a PIN prompt on a real terminal — so they
# are covered by test/RUN-THESE.sh instead, and asserted here only to the extent
# that they fail *correctly* when no TTY is available.
set -uo pipefail

HWVAULT="${HWVAULT_BIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/hwvault}"

# ------------------------------------------------------------------ harness --
declare -i PASS=0 FAIL=0
readonly C_RED=$'\033[31m' C_GRN=$'\033[32m' C_YEL=$'\033[33m' C_DIM=$'\033[2m' C_OFF=$'\033[0m'
FAILED_NAMES=()

t_start() { printf '%s· %s%s' "$C_DIM" "$1" "$C_OFF"; CURRENT="$1"; }
t_pass()  { PASS+=1; printf '\r%s✓%s %s\033[K\n' "$C_GRN" "$C_OFF" "$CURRENT"; }
t_fail()  { FAIL+=1; FAILED_NAMES+=("$CURRENT")
            printf '\r%s✗%s %s\033[K\n' "$C_RED" "$C_OFF" "$CURRENT"
            [[ -n "${1:-}" ]] && printf '    %s%s%s\n' "$C_DIM" "$1" "$C_OFF"; }

# assert helpers ------------------------------------------------------------
ok_eq() {  # name, expected, actual
  t_start "$1"
  if [[ "$2" == "$3" ]]; then t_pass; else t_fail "expected '$2', got '$3'"; fi
}
ok_contains() {  # name, needle, haystack
  t_start "$1"
  if [[ "$3" == *"$2"* ]]; then t_pass; else t_fail "expected to contain '$2'
    got: $(printf '%s' "$3" | head -3)"; fi
}
ok_fails() {  # name, command...
  local name="$1"; shift
  t_start "$name"
  if "$@" >/dev/null 2>&1; then t_fail "command unexpectedly succeeded"; else t_pass; fi
}
ok_succeeds() {  # name, command...
  local name="$1"; shift
  t_start "$name"
  local out
  if out="$("$@" 2>&1)"; then t_pass; else t_fail "$(printf '%s' "$out" | head -3)"; fi
}
ok_file() {  # name, path
  t_start "$1"
  if [[ -f "$2" ]]; then t_pass; else t_fail "missing file: $2"; fi
}
ok_no_file() {
  t_start "$1"
  if [[ ! -e "$2" ]]; then t_pass; else t_fail "file should not exist: $2"; fi
}

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g'; }

# ------------------------------------------------------------------ fixture --
# Isolated vault so the suite never touches the real recipients.
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/hwvault-test.XXXXXX")"
export HWVAULT_DIR="$SANDBOX"
cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT INT TERM

setup_recipients() {
  mkdir -p "$SANDBOX/recipients"
  # A real age keypair standing in for the backup recipient.
  age-keygen -o "$SANDBOX/recipients/recovery-key.txt" 2>&1 \
    | grep -o 'age1[a-z0-9]*' > "$SANDBOX/recipients/recovery.pub"
  chmod 600 "$SANDBOX/recipients/recovery-key.txt"
  # A second keypair standing in for the FIDO recipient. Encryption to it works
  # without hardware (public-key op); only *decryption* would need the token,
  # which is exactly why the FIDO decrypt path isn't automated here.
  age-keygen -o "$SANDBOX/recipients/fido-identity.txt" 2>&1 \
    | grep -o 'age1[a-z0-9]*' > "$SANDBOX/recipients/fido.pub"
  chmod 600 "$SANDBOX/recipients/fido-identity.txt"
}

hv() { "$HWVAULT" "$@"; }

# -------------------------------------------------------------------- tests --
echo
echo "hwvault test suite"
echo "  binary:  $HWVAULT"
echo "  sandbox: $SANDBOX"
echo

command -v age >/dev/null 2>&1 || { echo "FATAL: age not installed"; exit 1; }
[[ -x "$HWVAULT" ]] || { echo "FATAL: not executable: $HWVAULT"; exit 1; }

echo "── meta ─────────────────────────────────────────────"
ok_succeeds "runs --version"            hv --version
ok_contains "reports version"    "0.1"  "$(hv --version)"
ok_contains "help lists commands" "encrypt" "$(hv help)"
ok_fails    "rejects unknown command"   hv definitely-not-a-command

echo
echo "── recipient enforcement (SPEC §7) ──────────────────"
mkdir -p "$SANDBOX/recipients"
echo "data" > "$SANDBOX/lone.txt"
# With zero recipients configured, encryption must refuse outright.
ok_fails "refuses encrypt with 0 recipients" hv encrypt "$SANDBOX/lone.txt"
ok_contains "explains the refusal" "2 recipients" \
  "$(hv encrypt "$SANDBOX/lone.txt" 2>&1 | strip_ansi)"
ok_file  "leaves plaintext intact after refusal" "$SANDBOX/lone.txt"

# With only ONE recipient it must still refuse — a single point of loss.
age-keygen -o "$SANDBOX/recipients/recovery-key.txt" 2>&1 \
  | grep -o 'age1[a-z0-9]*' > "$SANDBOX/recipients/recovery.pub"
ok_fails "refuses encrypt with only 1 recipient" hv encrypt "$SANDBOX/lone.txt"
# Assert WHICH guard fired. Failing for the wrong reason (e.g. the downstream
# stanza sanity-check) would still "fail", masking a weakened §7 guard — a
# mutation test caught exactly that.
ok_contains "1-recipient refusal comes from the §7 guard, not a later check" \
  "fewer than 2 recipients" "$(hv encrypt "$SANDBOX/lone.txt" 2>&1 | strip_ansi)"
ok_file  "still leaves plaintext intact" "$SANDBOX/lone.txt"
rm -rf "$SANDBOX/recipients"

echo
echo "── encrypt ──────────────────────────────────────────"
setup_recipients
SECRET="test-secret-$RANDOM-$RANDOM"
echo "$SECRET" > "$SANDBOX/a.txt"
ok_succeeds "encrypts a file"                hv encrypt "$SANDBOX/a.txt"
ok_file     "produces .age"                  "$SANDBOX/a.txt.age"
ok_no_file  "removes the plaintext original" "$SANDBOX/a.txt"
ok_eq       "ciphertext has 2 recipients" "2" \
            "$(head -c 4096 "$SANDBOX/a.txt.age" | grep -c '^-> ')"
ok_contains "content round-trips via backup" "$SECRET" \
            "$(age -d -i "$SANDBOX/recipients/recovery-key.txt" "$SANDBOX/a.txt.age" 2>/dev/null)"

echo "x" > "$SANDBOX/a.txt"
ok_fails    "refuses to overwrite existing .age" hv encrypt "$SANDBOX/a.txt"
ok_file     "original kept when overwrite refused" "$SANDBOX/a.txt"
rm -f "$SANDBOX/a.txt"

ok_fails "refuses to double-encrypt a .age"  hv encrypt "$SANDBOX/a.txt.age"
ok_fails "rejects a missing file"            hv encrypt "$SANDBOX/nope.txt"
ok_fails "rejects a directory"               hv encrypt "$SANDBOX"

# The pre-delete verification: if age somehow emits a file with <2 recipients,
# encrypt must abort and KEEP the plaintext rather than delete it. Simulated by
# hiding a recipient after the guard would have passed — the stanza count in the
# OUTPUT is what must be checked, not just the config.
t_start "encrypt keeps plaintext if output has too few recipients"
_probe="$SANDBOX/probe.txt"; echo "probe" > "$_probe"
mv "$SANDBOX/recipients/fido.pub" "$SANDBOX/fido.hidden"
_out="$(hv encrypt "$_probe" 2>&1 | strip_ansi)"; _rc=$?
mv "$SANDBOX/fido.hidden" "$SANDBOX/recipients/fido.pub"
if (( _rc != 0 )) && [[ -f "$_probe" && ! -e "$_probe.age" ]]; then t_pass
else t_fail "rc=$_rc plaintext_exists=$([[ -f "$_probe" ]] && echo y || echo n) ciphertext=$([[ -e "$_probe.age" ]] && echo y || echo n)"; fi
rm -f "$_probe" "$_probe.age"

echo
echo "── binary + edge-case payloads ──────────────────────"
printf 'line1\nline2\n\xff\xfe binary \x00 bytes\n' > "$SANDBOX/bin.dat"
BIN_SUM="$(shasum -a256 "$SANDBOX/bin.dat" | awk '{print $1}')"
ok_succeeds "encrypts binary content" hv encrypt "$SANDBOX/bin.dat"
age -d -i "$SANDBOX/recipients/recovery-key.txt" "$SANDBOX/bin.dat.age" > "$SANDBOX/bin.out" 2>/dev/null
ok_eq "binary content is byte-identical" "$BIN_SUM" \
      "$(shasum -a256 "$SANDBOX/bin.out" | awk '{print $1}')"

: > "$SANDBOX/empty.txt"
ok_succeeds "encrypts an empty file" hv encrypt "$SANDBOX/empty.txt"
ok_file     "empty file produces .age" "$SANDBOX/empty.txt.age"

printf 'no trailing newline' > "$SANDBOX/nonl.txt"
ok_succeeds "encrypts file without trailing newline" hv encrypt "$SANDBOX/nonl.txt"
ok_eq "preserves absence of trailing newline" "no trailing newline" \
      "$(age -d -i "$SANDBOX/recipients/recovery-key.txt" "$SANDBOX/nonl.txt.age" 2>/dev/null)"

echo "spaces" > "$SANDBOX/name with spaces.txt"
ok_succeeds "handles filenames with spaces" hv encrypt "$SANDBOX/name with spaces.txt"
ok_file     "space-named .age exists" "$SANDBOX/name with spaces.txt.age"

echo
echo "── recover (backup path, no hardware) ───────────────"
ok_contains "recovers via backup identity" "$SECRET" \
            "$(hv recover "$SANDBOX/a.txt.age" 2>/dev/null)"
ok_fails    "recover rejects a missing file" hv recover "$SANDBOX/nope.age"
mv "$SANDBOX/recipients/recovery-key.txt" "$SANDBOX/bk.hidden"
ok_fails    "recover fails without a backup identity" hv recover "$SANDBOX/a.txt.age"
mv "$SANDBOX/bk.hidden" "$SANDBOX/recipients/recovery-key.txt"

echo
echo "── TTY guards (FIDO paths must fail fast) ───────────"
# These run without a TTY, so they must fail *before* reaching the token
# rather than hanging or emitting a confusing age error.
for sub in decrypt edit; do
  out="$(hv "$sub" "$SANDBOX/a.txt.age" 2>&1 | strip_ansi)"
  ok_contains "$sub reports the missing TTY clearly" "no TTY available" "$out"
done
out="$(hv exec "$SANDBOX/a.txt.age" -- true 2>&1 | strip_ansi)"
ok_contains "exec reports the missing TTY clearly" "no TTY available" "$out"

ok_fails    "exec requires a command"        hv exec "$SANDBOX/a.txt.age"
ok_contains "exec explains the missing command" "no command given" \
            "$(hv exec "$SANDBOX/a.txt.age" 2>&1 | strip_ansi)"
ok_fails    "exec rejects a missing file"    hv exec "$SANDBOX/nope.age" -- true

echo
echo "── status ───────────────────────────────────────────"
STATUS="$(hv status 2>&1 | strip_ansi)"
ok_contains "reports the vault path"      "$SANDBOX"        "$STATUS"
ok_contains "reports age tooling"         "age"             "$STATUS"
ok_contains "lists the fido recipient"    "$(cat "$SANDBOX/recipients/fido.pub")"   "$STATUS"
ok_contains "lists the backup recipient"  "$(cat "$SANDBOX/recipients/recovery.pub")" "$STATUS"
ok_contains "audits encrypted files"      "2 recipients"    "$STATUS"
ok_contains "warns the backup key is on disk" "move it offline" "$STATUS"
ok_contains "names the directory it scanned"  "scanned:"    "$STATUS"

# Once the recovery key is moved offline (SPEC §10 ③) its absence is the GOAL
# state, not an error: encryption must keep working from the .pub alone, and
# init must NOT regenerate — doing so would silently orphan the offline key.
mv "$SANDBOX/recipients/recovery-key.txt" "$SANDBOX/offline.key"
ok_contains "status reports the recovery key as offline" "recovery key is offline" \
            "$(hv status 2>&1 | strip_ansi)"
echo "offline-probe" > "$SANDBOX/off.txt"
ok_succeeds "encrypt still works with the recovery key offline" hv encrypt "$SANDBOX/off.txt"
ok_eq "still encrypts to 2 recipients" "2" \
      "$(head -c 4096 "$SANDBOX/off.txt.age" | grep -c '^-> ')"
_pub_before="$(cat "$SANDBOX/recipients/recovery.pub")"
hv init >/dev/null 2>&1 || true
ok_eq "init does NOT regenerate the recovery key when it is offline" \
      "$_pub_before" "$(cat "$SANDBOX/recipients/recovery.pub")"
ok_contains "offline key still decrypts what was encrypted meanwhile" "offline-probe" \
            "$(age -d -i "$SANDBOX/offline.key" "$SANDBOX/off.txt.age" 2>/dev/null)"
mv "$SANDBOX/offline.key" "$SANDBOX/recipients/recovery-key.txt"
rm -f "$SANDBOX/off.txt.age"

# The audit's whole purpose: catch a file only one recipient can open.
age -R "$SANDBOX/recipients/fido.pub" -o "$SANDBOX/single.age" <<<"lonely" 2>/dev/null
ok_contains "flags a single-recipient file as a loss risk" "SINGLE POINT OF LOSS" \
            "$(hv status 2>&1 | strip_ansi)"
rm -f "$SANDBOX/single.age"

echo
echo "── isolation ────────────────────────────────────────"
# HWVAULT_DIR must fully redirect the vault; the real one stays untouched.
REAL="$HOME/workspace/Projects/MiixKey/recipients/fido.pub"
if [[ -f "$REAL" ]]; then
  ok_contains "HWVAULT_DIR isolates from the real vault" "$SANDBOX" "$(hv status 2>&1 | strip_ansi)"
  t_start "real vault recipients untouched by the suite"
  if grep -q "$(cat "$REAL")" <<<"$STATUS"; then t_fail "sandbox status leaked the real recipient"; else t_pass; fi
fi

# ------------------------------------------------------------------ summary --
echo
echo "─────────────────────────────────────────────────────"
printf '%s%d passed%s' "$C_GRN" "$PASS" "$C_OFF"
(( FAIL )) && printf ', %s%d failed%s' "$C_RED" "$FAIL" "$C_OFF"
printf '\n'
if (( FAIL )); then
  printf '\nFailed:\n'; printf '  %s\n' "${FAILED_NAMES[@]}"
fi
echo
printf '%sNot covered here (needs PIN + touch on a real terminal): FIDO decrypt,\n' "$C_YEL"
printf 'edit round-trip, exec injection. Run test/RUN-THESE.sh for those.%s\n' "$C_OFF"
echo

exit $(( FAIL > 0 ))

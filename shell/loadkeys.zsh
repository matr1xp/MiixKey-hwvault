# hwvault — on-demand API key loading
#
# Replaces `source ~/.env`. Keys are NOT in your environment until you ask for
# them, so a shell that never calls loadkeys never holds them. Costs one
# PIN + touch per shell that needs them.

loadkeys() {
  # The trim patterns below need EXTENDED_GLOB; localoptions keeps it scoped to
  # this function so the user's shell settings are untouched.
  setopt localoptions extendedglob
  local vault="${HWVAULT_ENV:-$HOME/.env.age}"
  if [[ ! -f "$vault" ]]; then
    print -u2 "loadkeys: no encrypted env at $vault"
    return 1
  fi
  if [[ -n "${HWVAULT_KEYS_LOADED:-}" ]]; then
    print "loadkeys: already loaded in this shell (unset HWVAULT_KEYS_LOADED to reload)"
    return 0
  fi

  local content
  # Command substitution keeps plaintext in memory only — never a temp file.
  content="$(hwvault decrypt "$vault")" || { print -u2 "loadkeys: decryption failed"; return 1; }

  local -i n=0 line_no=0
  local line key val
  local names=""
  while IFS= read -r line; do
    (( line_no++ ))
    line="${line##[[:space:]]#}"                        # ltrim
    line="${line%%[[:space:]]#}"                        # rtrim
    [[ -z "$line" || "$line" == \#* ]] && continue      # blank or comment
    line="${line#export }"; line="${line##[[:space:]]#}"
    [[ "$line" == *=* ]] || { print -u2 "loadkeys: line $line_no not KEY=VALUE, skipped"; continue; }
    key="${line%%=*}"; val="${line#*=}"
    key="${key%%[[:space:]]#}"
    [[ "$key" == [A-Za-z_]*([A-Za-z0-9_]) ]] || { print -u2 "loadkeys: bad name '$key', skipped"; continue; }
    # strip one layer of matching quotes
    if [[ "$val" == \"*\" || "$val" == \'*\' ]]; then val="${val:1:${#val}-2}"; fi
    export "$key=$val"
    names="$names $key"
    (( n++ ))
  done <<< "$content"
  unset content

  # Record the names (not values) so unloadkeys can clear them without
  # decrypting again — works with the token unplugged.
  export HWVAULT_LOADED_NAMES="${names# }"
  export HWVAULT_KEYS_LOADED=1
  print "loadkeys: exported $n key(s) into this shell"
}

# Drop the keys again without closing the shell.
#
# Remembers which names loadkeys exported, so clearing needs no decryption —
# no PIN, no touch, and it still works with the key unplugged. (The previous
# version re-decrypted and parsed with GNU-only `sed ;t;d`, which BSD sed on
# macOS rejects with "undefined label".)
unloadkeys() {
  setopt localoptions extendedglob
  if [[ -z "${HWVAULT_KEYS_LOADED:-}" ]]; then
    print "unloadkeys: nothing loaded in this shell"
    return 0
  fi
  local -i n=0
  local k
  for k in ${(s: :)HWVAULT_LOADED_NAMES}; do
    [[ -n "$k" ]] || continue
    unset "$k" && (( n++ ))
  done
  unset HWVAULT_KEYS_LOADED HWVAULT_LOADED_NAMES
  print "unloadkeys: cleared $n key(s) from this shell"
}

# Startup hint. Shown only when there is something to load and it isn't loaded
# yet, so it stays quiet in shells that already have keys — and never blocks.
_hwvault_hint() {
  [[ -o interactive ]] || return          # never in scripts
  [[ -z "${HWVAULT_KEYS_LOADED:-}" ]] || return
  [[ -f "${HWVAULT_ENV:-$HOME/.env.age}" ]] || return
  print -P "%F{yellow}🔑 API keys are encrypted — run %B loadkeys %b to load them.%f"
}
# NOTE: intentionally NOT called here. ~/.zshrc invokes _hwvault_hint as its
# last line so the reminder lands below neofetch instead of scrolling away.

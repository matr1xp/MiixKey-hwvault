# Hardware-Bound Secrets Vault (`hwvault`)

**Encrypt files so they can only be decrypted with a physical touch on the MiixKey.**

Status: **Phases 1–3 complete, §10 gate cleared** — `hwvault` v0.1.0 on PATH, 53 tests
passing, both decrypt paths verified on hardware. Phase 4 (real secrets) unblocked.
Owner: Marlon Santos
Created: 2026-09-06

> ⚠️ **Dependency maturity gate.** The core dependency,
> `age-plugin-fido2-hmac`, is at **v0.5.0** and carries an upstream warning:
> *"Please consider this plugin to be experimental until the version v1.0.0 is published!"*
> **Gate conditions ①–④ were satisfied 2026-09-06** (see §10); ⑤ is an ongoing policy.
> Real secrets may now be migrated — but never as the only copy, and
> `Passwords.kdbx` stays on hold until upstream v1.0.0.

---

## 1. Problem

Secrets currently sit in plaintext across this machine: `.env` files, GCP service-account
JSON, API tokens, and a `Passwords.kdbx` on the MiixKey's own USB partition. Every one of
them is readable by any process running as the user, any backup that sweeps the directory,
and anyone who walks up to an unlocked laptop.

The usual fix — a passphrase-encrypted vault — moves the problem rather than solving it.
A passphrase can be phished, keylogged, shoulder-surfed, brute-forced offline, or simply
forgotten.

## 2. Goal

Make the decryption key **unavailable at rest**: derived on demand from the MiixKey's
FIDO2 `hmac-secret` extension, requiring PIN + touch, and never written to disk.

Steal the laptop, the backups, and the ciphertext — without the physical key in hand, the
files are unopenable.

**Precision on the claim.** The hardware gates *derivation*, not the derived identity's
subsequent use. Upstream states plainly:

> *"If this identity is stolen from memory, it can be used without the token to decrypt
> past and future data meant for this identity."*

So the guarantee is **"no key material at rest"**, not "no key material ever extractable".
An attacker with live memory access on an unlocked machine during a decrypt can lift the
identity and reuse it thereafter without the token. This is the same boundary as §6:
strong against offline and remote attacks, not against a live compromise of the running
host. Minimise exposure by keeping decrypt windows short (`exec`, not long-lived shells).

### Non-goals

- Not a password manager (KeePassXC/`Passwords.kdbx` keeps that job)
- Not multi-user or key-sharing
- Not a replacement for cloud KMS in server contexts
- No custom cryptography — this composes vetted tools only

## 3. Why this is possible

Confirmed on the actual device via CTAP2 `GetInfo` (2026-09-04):

```
Versions   : U2F_V2, FIDO_2_0, FIDO_2_1
Extensions : credBlob, credProtect, hmac-secret, largeBlobKey
Options    : rk, credMgmt, clientPin, largeBlobs, pinUvAuthToken, makeCredUvNotRqd
AAGUID     : 96da9e246eeaf3bc1123ee5b09280dfa
```

`hmac-secret` is the load-bearing capability. It lets the authenticator act as a hardware
KDF: given a credential and a salt, it returns a stable 32-byte secret, computed inside the
secure element. The same salt always yields the same output on the same key — and no
other key can reproduce it.

That is exactly the primitive a symmetric file-encryption tool needs.

## 4. Architecture

```
                    ┌──────────────────────────────┐
   plaintext ──────▶│  age -R vault.pub            │──────▶ secrets.age
   (.env, keys)     │  (public-key encryption)     │        (safe at rest,
                    └──────────────────────────────┘         safe in git)

                    ┌──────────────────────────────┐
   secrets.age ────▶│  age -d -i vault.key         │──────▶ plaintext
                    │            │                 │        (stdout / tmpfs)
                    └────────────┼─────────────────┘
                                 ▼
                    ┌──────────────────────────────┐
                    │ age-plugin-fido2-hmac        │
                    │   → CTAP2 hmac-secret        │
                    │   → PIN prompt + TOUCH       │───── MiixKey (USB)
                    │   → 32-byte key, in memory   │
                    └──────────────────────────────┘
```

**Key property:** encryption needs only `vault.pub` (no hardware). Decryption needs the
physical MiixKey. This asymmetry means CI, scripts, and other machines can *write* secrets
without ever holding the ability to *read* them.

### Components

| Component | Role | Source |
|---|---|---|
| `age` 1.3.2 | File encryption | Homebrew (`brew install age`) |
| `age-plugin-fido2-hmac` | FIDO2 `hmac-secret` bridge | [olastor/age-plugin-fido2-hmac](https://github.com/olastor/age-plugin-fido2-hmac) — **not in Homebrew** |
| `libfido2` 1.17.0 | CTAP2 transport | already installed |
| MiixKey | Hardware root of trust | present |

### Credential design

Use **non-discoverable** (non-resident) credentials. Rationale:

- The MiixKey's resident-credential slots are finite and already partly consumed
  (the `ssh:miixkey` SSH key lives in one).
- Non-discoverable credentials store an opaque handle in `vault.key`; the handle is
  useless without the hardware, so it is safe to keep on disk and back up.
- This is the plugin's default and best-tested mode.

`vault.key` is therefore **not a secret** in the traditional sense — but treat it as
sensitive anyway (mode `600`), since losing it means losing access even with the key.

## 5. CLI surface

A thin wrapper (`hwvault`) over `age`, so day-to-day use is short and the ergonomics don't
push anyone back to plaintext.

```bash
hwvault init                      # create credential (PIN + touch), write vault.key/.pub
hwvault encrypt <file>            # file → file.age, shreds original on success
hwvault decrypt <file.age>        # → stdout (PIN + touch)
hwvault edit <file.age>           # decrypt → $EDITOR in tmpfs → re-encrypt
hwvault exec <file.age> -- <cmd>  # inject as env vars into a subprocess, never touch disk
hwvault status                    # key present? credential valid? files tracked?
hwvault rotate                    # re-encrypt everything to a new credential
```

`exec` is the important one — it's what makes the vault usable in real workflows:

```bash
hwvault exec prod.env -- terraform apply
hwvault exec gcp.age  -- gcloud compute instances list
```

Secrets reach the child process through the environment and never land on disk.

## 6. Threat model

### Defended

| Threat | Why it fails |
|---|---|
| Laptop stolen (powered off / locked) | Ciphertext only; no key present |
| Backup / cloud-sync exfiltration | `.age` files are opaque |
| Repo leak of committed secrets | Encrypted at rest, safe to commit |
| Malware reading `~/.env`, `~/.config` | Nothing to read but ciphertext |
| Offline brute force | No passphrase exists to guess |
| Phishing / keylogging | Key material never typed; PIN alone is useless without the hardware |

### NOT defended — stated plainly

| Threat | Reality |
|---|---|
| Malware present *while* you decrypt | It can read the plaintext or scrape the child's env. Hardware keys gate *access*, not *use*. |
| Identity lifted from process memory | Upstream: the stolen identity decrypts *past and future* data for that credential **without the token**. Rotate (§8 Phase 5) if a host compromise is suspected. |
| Physical theft of key + PIN | Full compromise. The PIN is the only barrier; pick a strong one. |
| Coercion | The key is in your pocket. It does not resist a person compelling you. |
| Lost/destroyed key | **Total, permanent data loss** without a backup credential. See §7. |
| Evil-maid firmware attack | Out of scope; a tampered device could exfiltrate. |

This is a **defense-in-depth** control that decisively raises the cost of remote and
offline attacks. It is not a defense against a live compromise of the running machine.

## 7. Recovery — the part that must not be an afterthought

Hardware-bound encryption fails catastrophically and irreversibly when the hardware is
lost. This is the single largest operational risk, larger than any attack in §6.

**Mandatory: encrypt every file to at least two recipients.**

```bash
age -R vault.pub -R recovery.pub -o secrets.age plaintext
```

Recovery options, in preference order:

1. **Second hardware key** (best) — a spare FIDO2 key with its own credential, stored
   offsite. Same security properties, no downgrade.
2. **Paper passphrase recipient** — a high-entropy passphrase written on paper in a safe.
   Weaker, but survives losing every device.
3. **Printed age identity** — the raw `AGE-SECRET-KEY-1…` on paper, offline.

**A vault with a single recipient is a bug, not a configuration.** `hwvault init` must
refuse to complete until a second recipient is registered, and `hwvault status` must warn
loudly whenever any tracked file has fewer than two.

## 8. Implementation phases

### Phase 1 — Foundation ✅ COMPLETE (2026-09-06)
- [x] `brew install age` — 1.3.2
- [x] Install `age-plugin-fido2-hmac` v0.5.0 (darwin/arm64 release → `~/.local/bin`)
- [x] **Version + binary SHA-256 recorded; tarball archived** → `vendor/PINNED.md` (§10 ①②)
- [x] Plugin-independent backup identity created + verified (§10 ③) → `recipients/`
- [x] Verify plugin sees the MiixKey; PIN + touch round-trip confirmed
- [x] Dual-recipient encrypt/decrypt verified end-to-end (§7)

**Verification results** (`test/RUN-THESE.sh`):

| Test | Result |
|---|---|
| FIDO decrypt, dual-recipient file | ✅ PIN + touch → plaintext |
| FIDO decrypt, FIDO-only file | ✅ PIN + touch → plaintext |
| **Negative: key unplugged** | ✅ `timed out waiting for device` — correctly failed |
| **Backup path, key unplugged** | ✅ decrypted — recovery hatch works |

Encryption required **no hardware** (done from an automated session); decryption required
the physical key. The asymmetry in §4 is confirmed in practice.

### Phase 2 — Vault ◐ IN PROGRESS (2026-09-06)
- [x] `hwvault init` — credential creation, dual-recipient enforcement
- [x] `encrypt` / `decrypt` with atomic writes and safe original-file handling
- [x] `recover` — recovery-key path, no hardware (§10 ③)
- [x] `status` — tooling, recipients, hardware presence, recipient-count audit
- [x] Automated test suite — `test/test_hwvault.sh`, 48 assertions, fully unattended
- [x] Install onto PATH — symlinked `~/.local/bin/hwvault` → repo (edits take effect
      immediately, no reinstall)

### Phase 3 — Ergonomics ◐ IN PROGRESS (2026-09-06)
- [x] `exec` — env injection into a subprocess, plaintext never on disk
- [x] `edit` — decrypt → `$EDITOR` → re-encrypt, temp file shredded on all exit paths
- [x] Shell completions — zsh, symlinked into `~/.oh-my-zsh/completions/_hwvault`

`exec` dotenv parsing verified against edge cases: `export` prefix, single/double
quotes, empty values, `A=b=c` (splits on first `=` only), trailing whitespace in keys.
Invalid lines are **warned, not silently skipped** — a silently-missing secret is worse
than a loud failure.

**Testing.** `test/test_hwvault.sh` runs unattended in an isolated sandbox
(`HWVAULT_DIR` → temp dir), so it never touches the real recipients. It covers recipient
enforcement, encrypt/recover round-trips, binary and empty payloads, filenames with
spaces, error paths, `status` auditing, and that the FIDO paths fail *fast and clearly*
without a TTY. The FIDO paths themselves (PIN + touch) cannot be automated — those stay
in `test/RUN-THESE.sh`.

The suite was mutation-tested. Two mutations initially passed undetected and both are
now covered:

| Mutation | Initially | Fix |
|---|---|---|
| §7 dual-recipient guard weakened (`>=4` → `>=2`) | ❌ undetected — the command still failed, just via a later check | assert *which* guard fires, not merely that it fails |
| `encrypt` pre-delete stanza verification removed | ❌ undetected | assert plaintext survives when output has too few recipients |
| TTY guard removed | ✅ detected (test hangs on the token — itself the proof the guard matters) | — |

Asserting an outcome is not the same as asserting the mechanism; a command that fails for
the wrong reason still looks green.

`edit` caveat: macOS has no tmpfs by default, so plaintext does touch disk during
editing. Mitigated with mode 600 in `$TMPDIR` and a `trap … EXIT INT TERM HUP` that
shreds it on every exit path — but APFS erase remains best-effort, and the command
says so.

Implemented at `bin/hwvault` (v0.1.0). Behaviours verified:

| Behaviour | Result |
|---|---|
| Encrypt targets both recipients | ✓ 2 stanzas, verified before original removed |
| Refuses < 2 recipients | ✓ hard fail (§7) |
| Refuses overwrite / double-encrypt / missing file | ✓ |
| `recover` via backup identity, no hardware | ✓ |
| TTY guard fails fast with actionable message | ✓ (tests an actual open, not `-e /dev/tty`) |
| `status` flags single-recipient files | ✓ caught both Phase 1 fixtures |
| `decrypt` against hardware (PIN + touch) | ✓ verified on device |

Known limitation: `shred` is best-effort only — on APFS (copy-on-write, snapshots)
overwriting blocks does not guarantee the plaintext is unrecoverable. `encrypt` says so
explicitly rather than implying a guarantee it cannot make.

### Phase 3 — Ergonomics
- [ ] `exec` — env injection into a subprocess
- [ ] `edit` — tmpfs round-trip, never writing plaintext to persistent storage
- [x] Shell completions — zsh, symlinked into `~/.oh-my-zsh/completions/_hwvault`

### Phase 4 — Adoption ✅ UNBLOCKED (gate cleared 2026-09-06)
- [x] Confirm §10 gate satisfied (pinned, archived, plugin-independent recovery recipient,
      recovery rehearsed) **before** migrating anything irreplaceable
- [ ] Migrate real secrets: `.env` files, GCP service-account JSON, API tokens —
      never as the only copy
- [ ] Pre-commit hook rejecting plaintext secrets
- [ ] Document the recovery drill — **and actually rehearse it** via the non-plugin path

### Phase 5 — Optional extensions
- [ ] `hwvault rotate` for credential rotation
- [ ] ~~Encrypt `Passwords.kdbx`~~ — **hold until upstream v1.0.0** (§10): highest-value,
      least-replaceable data should not sit behind an experimental plugin
- [ ] Wire into the CI/CD physical-presence gate (separate project)

## 9. Constraints and known pitfalls

Discovered during environment survey (2026-09-06) — these will bite otherwise:

1. **TTY required.** PIN prompts need a real terminal. Inside Claude Code's automated Bash
   tool the prompt gets no TTY and fails with a misleading "incorrect passphrase" or
   "PIN incorrect". Run all interactive vault operations from Terminal/iTerm or via `!`.
   (Same failure mode already hit during SSH key generation.)

2. **Browsers hold the FIDO device exclusively.** Edge, Chrome, and Comet each open a
   USB handle on the key. Quit them before credential creation, or the operation fails
   with a device I/O error.

3. **NRF mode matters.** The key must be in `NFC+BT` mode, not `Chameleon` — Chameleon
   mode repurposes the radio and disables FIDO paths.

4. **Never flash stock Chameleon Ultra firmware.** ChameleonUltraGUI's *Update* button
   pushes firmware that removes the FIDO applet and bricks this entire workflow. NRF
   firmware comes only from MiixPro.

5. **PIN retry counter resets to 8** on device re-enumeration, so failed attempts are
   recoverable — but a genuine exhaustion factory-resets the FIDO application and
   destroys every credential, including the vault's.

6. **`age-plugin-fido2-hmac` is not in Homebrew.** No `brew upgrade` path; pin the version
   and track upstream releases manually.

## 10. Dependency maturity gate

`age-plugin-fido2-hmac` is **v0.5.0**, pre-1.0, and upstream explicitly asks users to treat
it as experimental. `age` itself is stable (1.3.2) and not in question — the risk is
entirely in the plugin.

### What pre-1.0 actually risks here

| Risk | Consequence | Mitigation |
|---|---|---|
| **Wire-format change** between versions | Old `.age` files stop decrypting after an upgrade | Pin the version; keep the pinned binary archived alongside the ciphertext; never upgrade without a rehearsed re-encrypt |
| **Credential-derivation change** | The same key derives a *different* secret → permanent loss | Same pin-and-archive discipline; verify decrypt after any upgrade before deleting anything |
| **Undiscovered crypto bug** | Confidentiality weaker than believed | Do not use as the sole protection for high-value secrets yet |
| **Upstream abandonment** | No fixes, no macOS build updates | Archive a working binary + source tarball locally |

The repo ships `docs/spec-v2.md`, which means the format has **already revised at least
once**. Treat format stability as an open question, not a given.

### Gate conditions — required before Phase 4 (real secrets)

**Status: ①–④ SATISFIED 2026-09-06.** Recovery key generated, moved offline, and
*rehearsed against real ciphertext* — twice: once against a canary, and again against a
file encrypted **after** the key went offline, which is the guarantee that actually
matters ongoing. FIDO credential regenerated fresh (the Phase 1 one was burned by
passing through a chat transcript) and verified on hardware.


1. **Pin the exact version.** Record the version and binary SHA-256 in this repo. No
   floating installs, no auto-upgrade.
2. **Archive the toolchain.** Keep the working plugin binary *and* its source tarball
   with the vault. A future macOS that won't run the old binary is a real scenario.
3. **Dual-recipient is non-negotiable** (§7) — and the second recipient must **not**
   depend on this plugin. A paper passphrase or plain `age` identity means a plugin
   format break is an inconvenience, not a catastrophe.
4. **Rehearse recovery via the non-plugin path** before migrating anything real.
5. **Re-verify after every upgrade**: decrypt a known file with the new version *before*
   trusting it, and keep the old binary until that passes.

### Revised adoption posture

- **Phases 1–3: proceed.** Build and use it on low-stakes, reproducible data
  (throwaway files, dev `.env`s that can be regenerated).
- **Phase 4: gated.** Migrate genuinely irreplaceable secrets only after conditions 1–5
  hold, and even then never as the *only* copy.
- **Phase 5 (`Passwords.kdbx`): hold.** The password database is the highest-value,
  least-replaceable target on the device. Do not put it behind an experimental plugin.
  Revisit at v1.0.0.

This is not a reason to abandon the project — the design is sound and the primitive is
right. It is a reason to keep a plugin-independent escape hatch until upstream ships 1.0.

## 11. Success criteria

- [ ] A `.age` file cannot be decrypted on this Mac with the MiixKey unplugged
- [ ] The same file decrypts with the key present, in under 5 seconds including touch
- [ ] `hwvault exec` runs a real command with injected secrets, no plaintext on disk
- [ ] Recovery from the backup recipient is **rehearsed and verified**, not just documented
- [ ] At least three real secret files migrated out of plaintext
- [ ] `grep -r` across the home directory surfaces no plaintext credentials in tracked paths

---

## References

- [olastor/age-plugin-fido2-hmac](https://github.com/olastor/age-plugin-fido2-hmac) — plugin, releases, build notes
- [FiloSottile/age](https://github.com/FiloSottile/age) — file encryption tool
- [CTAP 2.1 `hmac-secret` extension](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension)
- Device capability evidence: CTAP2 `GetInfo`, §3 above

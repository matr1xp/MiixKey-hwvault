# MiixKey: hwvault

**Encrypt files so they can only be decrypted with a physical touch on a FIDO2 hardware key.**

`hwvault` is a thin bash wrapper over [`age`](https://github.com/FiloSottile/age) and
[`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac) that turns a
FIDO2 token's `hmac-secret` extension into a hardware root of trust for file encryption.

The key property: **encryption needs only public keys — decryption needs the physical
token, plus its PIN and a touch.** Scripts and CI can *write* secrets without ever being
able to *read* them. Steal the laptop, the backups, and the ciphertext, and it's all
ciphertext: no key material exists at rest to steal, guess, phish, or brute-force.

```
plaintext ──▶ age -R fido.pub -R recovery.pub ──▶ secrets.age   (safe at rest,
                                                             safe in git)

secrets.age ──▶ age -d -i fido-identity ──▶ PIN + touch ──▶ plaintext
                                                        (never written to disk)
```

Full design rationale, threat model, and phased rollout live in [SPEC.md](SPEC.md) —
that document is the source of truth for every decision made here.

## How it works

1. The FIDO2 token's CTAP2 `hmac-secret` extension acts as a **hardware KDF**: given a
   credential and a salt, the secure element returns a stable 32-byte secret. The same
   salt on the same key always derives the same secret; no other key can reproduce it.
2. `age-plugin-fido2-hmac` wraps that derivation into an ordinary `age` recipient /
   identity pair. The identity file holds only an opaque credential handle — useless
   without the hardware.
3. `hwvault` adds the operational discipline around it: dual-recipient enforcement,
   atomic writes, TTY guards, and secret injection into subprocesses.

No custom cryptography anywhere — vetted tools composed with a bash wrapper.

## CLI

```bash
hwvault init                      # create credential (PIN + touch), set up dual recipients
hwvault encrypt <file>            # file → file.age, original removed on verified success
hwvault decrypt <file.age>        # → stdout (PIN + touch)
hwvault recover <file.age>        # → stdout via offline recovery key, no hardware
hwvault edit <file.age>           # decrypt → $EDITOR → re-encrypt, temp shredded
hwvault exec <file.age> -- <cmd> # inject as env vars into a subprocess — never on disk
hwvault status                    # tooling, recipients, hardware presence, audits
```

`exec` is what makes the vault usable day to day:

```bash
hwvault exec prod.env -- terraform apply
hwvault exec gcp.age  -- gcloud compute instances list
```

Interactive shells get the same via `shell/loadkeys.zsh`:

```
🔑 API keys are encrypted — run  loadkeys  to load them.
```

## Two recipients, always

**Every file is encrypted to at least two recipients: the hardware key and an offline
recovery key.** A single-recipient vault is a single point of permanent loss — `hwvault`
refuses to encrypt with fewer than two, and `status` audits existing files and flags
any that are short.

The recovery recipient is deliberately **plugin-independent** (a plain `age` identity
kept offline — printed or on removable media). The core plugin is pre-1.0 upstream; a
format break must be an inconvenience, not a catastrophe.

## Threat model (short version)

**Defended:** stolen laptop, backup/cloud-sync exfiltration, committed-secrets repo
leaks, malware reading config files, offline brute force, phishing/keylogging (key
material is never typed).

**Not defended — stated plainly:** malware present *while* you decrypt; identity lifted
from process memory on a live-compromised host (upstream warns a stolen identity
decrypts without the token — rotate if you suspect it); physical theft of key + PIN;
coercion; and total permanent loss if both the key and the recovery copy are gone.

Hardware gates *access*, not *use*. This is defense-in-depth against remote and offline
attacks, not a defense against a live compromise of the running machine. The full
tables are in [SPEC.md §6](SPEC.md).

## Toolchain pinning

The plugin is pre-1.0 and treated accordingly: exact version and SHA-256s recorded in
[`vendor/PINNED.md`](vendor/PINNED.md), the binary and its source tarball archived in
`vendor/`, and the rule is simple — **never upgrade without decrypting a known file
with the new version first.** `Passwords.kdbx`-class data stays out until upstream
ships v1.0.0.

## Testing

- `test/test_hwvault.sh` — 53 assertions, fully unattended, runs in an isolated
  sandbox (`HWVAULT_DIR`) so it never touches real recipients. Mutation-tested: two
  initially-undetected mutations (a weakened guard, a removed verification step) are
  now explicitly covered.
- `test/RUN-THESE.sh` — the hardware paths (PIN + touch can't be automated):
  self-provisioning fixtures, FIDO decrypt round-trips, a negative unplug test, and
  the offline recovery drill.

```bash
bash test/test_hwvault.sh        # no hardware needed
bash test/RUN-THESE.sh           # real terminal + key plugged in
```

## Requirements

- `age` v1.3.2 (Homebrew), `age-plugin-fido2-hmac` v0.5.0 (pinned, not in Homebrew)
- A FIDO2 token with the `hmac-secret` extension
- bash 4+ (`mapfile`), macOS or Linux
- A real terminal for anything that prompts for the PIN — no TTY, no decrypt

## Status

v0.1.0 — Phases 1–3 complete (build, vault, ergonomics), dependency-maturity gate
cleared, both decrypt paths verified on hardware. See [SPEC.md §8](SPEC.md) for the
phase ledger and what remains before real secrets are migrated onto it.

## License

Personal project of [Marlon Santos](https://github.com/matr1xp). Not published under
a license yet — ask if you want to reuse the pattern; the underlying tools (`age`,
the plugin) carry their own licenses.
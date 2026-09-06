# Recipients

Every file is encrypted to **two** recipients (SPEC §7): the hardware path and the
recovery path. A single-recipient file is a single point of permanent loss.

| File | What | Secret? |
|---|---|---|
| `fido-identity.txt` | FIDO2 credential handle | handle only — useless without the MiixKey |
| `fido.pub` | age recipient, hardware path | no |
| `recovery-key.txt` | plain age private key — the escape hatch (§10 ③) | **YES — this is the crown jewel** |
| `recovery.pub` | age recipient, recovery path | no |

## `recovery-key.txt` — read this

This is a **plain age private key**. It is deliberately independent of
`age-plugin-fido2-hmac` so that a pre-1.0 format break, a lost MiixKey, or an abandoned
upstream cannot lock you out of your own data.

It is also the one file that can decrypt everything **without any hardware**. Treat it
accordingly:

- **Move it offline before Phase 4.** Print it, or put it on removable media in a safe.
  It must not live on the same disk as the ciphertext it protects — a single stolen
  laptop should not yield both.
- Never paste it anywhere. Never commit it.
- Rehearse recovery with the offline copy *before* trusting the vault with anything
  irreplaceable. An untested backup is not a backup.

Rotated 2026-09-06. The previous key is archived at
`~/.local/share/hwvault-old-keys/` — delete it once you are confident nothing is still
encrypted to it.

## ⚠️ `fido-identity.txt` is a throwaway

The current FIDO credential was generated during Phase 1 testing and its identity string
**passed through a chat transcript**, so it is considered burned. Not exploitable without
the physical MiixKey + PIN, but per upstream's warning about stolen identities, do not
reuse it for real secrets.

Before Phase 4: delete `fido-identity.txt` and `fido.pub`, then run `hwvault init` in a
real terminal to mint a fresh credential that never leaves the machine.

## Rotating a key

Regenerating a recipient **orphans every file already encrypted to the old one** — they
become recoverable only via the remaining recipient, which defeats §7. After any
rotation, re-encrypt existing files to both new recipients.

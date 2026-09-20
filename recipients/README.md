# Recipients

> **The live recipients now live in the vault directory** —
> `${HWVAULT_DIR:-~/.local/share/hwvault}/recipients` — a plain local folder
> that is **not** this git checkout and **not** cloud-synced. A `git pull`
> here must never be able to change what files get encrypted to
> (SPEC §6 operating assumptions). The copies of `fido.pub` / `recovery.pub`
> in this directory are **archival**, kept so history stays intelligible; do
> not encrypt to them directly. If they ever diverge from the vault's pinned
> recipients, trust the vault and re-encrypt.

Every file is encrypted to **two** recipients (SPEC §7): the hardware path and the
recovery path. A single-recipient file is a single point of permanent loss.

| File | What | Secret? |
|---|---|---|
| `fido.pub` | age recipient, hardware path (archival copy) | no |
| `recovery.pub` | age recipient, recovery path (archival copy) | no |

The live `fido-identity.txt` (credential handle) and `recovery-key.txt` live only
in the **vault directory**, never in this repo. The handle is untracked and
git-ignored here by policy — publishing it, combined with upstream's
stolen-identity caveat, is a wider exposure than the chat transcript that
burned the previous credential.

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
encrypted to it. The private key itself is **offline**; only `recovery.pub` remains on
this machine, in the vault directory.

## ⚠️ Credential history — read before rotating

The Phase-1 FIDO credential was **burned** (its identity string passed through a chat
transcript) and was regenerated on 2026-09-06; the current identity has never left
this machine. Per upstream's warning, a lifted identity can decrypt without the
token — that is why the handle is machine-local and never pushed.

**Rotation orphans.** Regenerating a recipient **orphans every file already
encrypted to the old one** — they become recoverable only via the remaining
recipient, which defeats §7. If you must rotate:

1. Consciously delete the vault's `recipients/pins` file first — `hwvault init`
   hard-fails while the pins point at the old recipients.
2. Run `hwvault init` in a real terminal (PIN + touch) to mint the new credential.
3. Re-encrypt **every** vault file to both new recipients.
4. Regenerate the committed canary (`test/verify.txt.age`) to the new recipients.

## Rotating a key

Regenerating a recipient **orphans every file already encrypted to the old one** — they
become recoverable only via the remaining recipient, which defeats §7. After any
rotation, re-encrypt existing files to both new recipients.

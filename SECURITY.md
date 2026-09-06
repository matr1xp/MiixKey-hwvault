# Security Policy

This repo is a personal security tool, and its own standards are the floor:
if you've found a weakness here, it matters. Reports in good faith are welcome
and appreciated — including reports of things that are "by design" but you
think shouldn't be.

## Scope

This covers the `hwvault` wrapper and this repo's contents (`bin/hwvault`,
test suite, shell integration). The heavier lifting is done by upstream
projects — vulnerabilities there should also be reported (and fixed) upstream:

- [FiloSottile/age](https://github.com/FiloSottile/age) — file encryption
- [olastor/age-plugin-fido2-hmac](https://github.com/olastor/age-plugin-fido2-hmac) — FIDO2 `hmac-secret` bridge
- Your authenticator's firmware (vendor-dependent)

**Out of scope** (documented, deliberate limits — see [SPEC.md §6](SPEC.md)):

- Malware running on the host *during* a decrypt (hardware gates access, not use)
- Key material lifted from process memory on a live-compromised host
- Physical theft of both the token and its PIN
- Coercion while the key is in your possession

If you believe one of these *is* practically exploitable in a way the spec
doesn't credit, that's a valid report — the spec being wrong is a bug.

## Supported versions

| Version | Supported |
| ------- | ---------- |
| 0.1.x   | ✅ (current development line) |
| < 0.1   | ❌ (none predate the first commit) |

There is no release cadence yet — this is a single-user tool with a
[dependency-maturity gate](SPEC.md) that deliberately lags upstream plugin
releases. Version pinning is a security *feature* here: see
[vendor/PINNED.md](vendor/PINNED.md).

## Reporting a vulnerability

Either channel works:

1. **GitHub private vulnerability reporting** (preferred) — use the
   *"Report a vulnerability"* link under the **Security** tab of this repo.
   This keeps the thread, discussion, and any CVE coordination in one place.
2. **Email** — [agent@marlsantos.com](mailto:agent@marlsantos.com), subject
   prefixed `SECURITY: hwvault`.

If the report contains sensitive details you'd rather not email, send just
the outline by email and the specifics through GitHub's channel (or ask for
an encrypted channel).

## What to expect

- **Acknowledgement** within **72 hours**.
- An assessment — accepted / declined / out-of-scope-upstream — within
  **7 days**, usually sooner for a repo this small.
- If accepted: a fix in `master` and credit in the commit and release notes,
  unless you prefer to stay anonymous. You'll be told the plan before
  anything is published.
- If declined: a written explanation of why, and the reasoning is open to
  challenge — I'd rather re-examine a "wrong" report twice than miss one.
- Coordinated disclosure is the default: please don't publish until the fix
  is out, or until we've agreed a timeline. If I go silent past a promised
  date, disclose as you see fit.

## Signed commits

All commits are GPG-signed with a hardware-backed (FIDO2) signing key.
Unsigned commits claiming to be from this project should be treated with
suspicion. Verify with `git log --show-signature`.
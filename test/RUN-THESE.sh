#!/bin/bash
# Phase 1 verification — run in a REAL terminal (needs TTY for PIN prompt)
cd ~/workspace/Projects/MiixKey
echo "=== TEST 1: FIDO decrypt of dual-recipient file (PIN + touch) ==="
age -d -i recipients/fido-identity.txt test/dual.age
echo
echo "=== TEST 2: FIDO decrypt of fido-only file (PIN + touch) ==="
age -d -i recipients/fido-identity.txt test/fido-only.age
echo
echo "=== TEST 3: NEGATIVE — unplug the MiixKey, press Enter, expect FAILURE ==="
read -r -p "Unplug the key now, then press Enter..."
age -d -i recipients/fido-identity.txt test/fido-only.age && echo "!!! UNEXPECTED: decrypted without key" || echo "✅ correctly FAILED without hardware"
echo
echo "=== TEST 4: backup path still works with key unplugged ==="
age -d -i recipients/recovery-key.txt test/dual.age && echo "✅ backup recovery works without hardware"

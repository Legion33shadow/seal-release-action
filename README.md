# LEGION SEAL release (GitHub Action)

Seals the SHA-256 of your release artifacts in the public [LEGION SEAL](https://seal.legion-api.com) log and writes a
badge, a proof link and offline-verification steps to the job summary.

> **Claim boundary.** A receipt proves that this artifact's SHA-256 was recorded in the log at this date (the registry's
> declared clock, not a qualified timestamp). It does **NOT** prove that the artifact is free of defects or malware, who
> built it, or where it came from. LEGION SEAL has a **single operator and no independent witness yet**; no Bitcoin
> anchoring. Rules: https://seal.legion-api.com/seal/v1/rules

## What is sent
For each file, exactly one request: `POST https://seal.legion-api.com/seal/v1/submit` with
`{"sha256": "<64 hex>", "label": "build <owner/repo>@<commit7>"}`.
The artifact itself is never sent. The action reads no secret and needs no token. The label is public.

## Usage
```yaml
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  seal:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make dist            # build your artifacts
      - id: seal
        uses: Legion33shadow/seal-release-action@v1
        with:
          files: dist/*
      - uses: actions/upload-artifact@v4
        with:
          name: seal-receipts
          path: seal-receipts/
```
The job summary then shows, per file: sha256, leaf index, proof link, and a badge:
```
[![sealed](https://seal.legion-api.com/seal/v1/badge/N.svg)](https://seal.legion-api.com/seal/v1/proof/N)
```
The badge reads `sealed · #N · <date>`, nothing more.

## Verify offline
```
curl -sO https://raw.githubusercontent.com/Legion33shadow/legion-seal/main/verify_seal.py
python3 verify_seal.py FILE.seal-N.json --file FILE      # RESULTAT: VALIDE, or RESULTAT: INVALID
```
The action also verifies each receipt on the runner with the bundled `verify_seal.py` (byte-identical to the live
verifier) and the pinned registry key, when Python `cryptography` is installed; otherwise the check is reported as skipped.

## Limits (measured from the registry rules)
- 6 submissions per minute and 100 per day per IP; shared GitHub-hosted runners share IPs. The action retries after a 429.
- A seal is never refused for a Genesis quota (registry rules v1). A build receipt needs no Genesis number: past the
  first 1000 leaves, receipts simply carry `in_genesis: false`, and the action treats that as a normal success.
- If the registry is unreachable or rate-limits you after retries, the step warns (or fails with `fail-on-error: true`).
- The same SHA-256 sealed twice returns the first entry.
- Prototype service; it can be withdrawn (rules §6).

## Inputs
`files` (required), `label-prefix` (`build`), `receipts-dir` (`seal-receipts`), `fail-on-error` (`false`),
`base-url`, `test` (`false`; `true` sends `X-Legion-Test`, excluded from the registry's counters and feed).

License: MIT.

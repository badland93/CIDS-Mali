# CIDS-Mali Prototype Test Report

Run date: 2026-10-23

## Automated suite

Command: `python -m pytest -q`

Result: **36 passed in 5.17 seconds** in the workspace-selected Python 3.14 environment.

Coverage includes AES-256-CBC/PKCS7 UTF-8 round trips, unique IVs, wrong-key failure, RSA-2048 signature round trips and tamper detection, canonical JSON, key-file protection and no AES-key regeneration, card issuance, QR/PNG/PDF generation, expiry/replay/revocation/wrong-issuer paths, consent enforcement, encrypted SQLite fields and revocation reasons, SQL injection handling, XSS escaping, path traversal, CSRF, role enforcement, login throttling, and erasure.

## Local timing sample

One representative synthetic student and generated image on the development container:

| Check | Observed | Target | Result |
| --- | ---: | ---: | --- |
| Full issue and artifact generation | 0.2972 s | < 5 s | Pass in this environment |
| Python offline verification | 0.00028 s | < 2 s | Pass in this environment |
| Compact QR JSON | 835 bytes | approximately < 800 bytes | Slightly above target |

These are one-sample container measurements, not a benchmark certification for a Core i3 / 4 GB Windows or Ubuntu school machine. The QR value contains all required signed fields and a 2048-bit RSA signature; no required personal-data field or signature protection was removed to reduce its size.

## Locust smoke load

An isolated temporary Flask instance, temporary SQLite DB/keys, 50 prepared secretary accounts, 50 configured virtual users, and an 8-second headless run produced:

- `POST /verify`: 519 requests, 0 failures (0.00%)
- Average verification-route response: 37 ms; median: 13 ms
- Aggregate rate across the run: 86.50 requests/second, including login and page setup
- Locust process exit: 0

This brief smoke run meets the error-rate target for the executed sample and exceeds 500 verification requests in the run window. It does not establish sustained performance for an hour, validate 50 devices on a real exam-centre network, or measure the requested low-end hardware. Repeat a longer run on the intended school hardware/network before operational use.

## Not verified in this run

- Browser camera/Web Crypto behavior was reviewed and server/static asset checks passed, but no real Android browser/device compatibility matrix was run. `BarcodeDetector` is not available in every browser; the paste fallback remains.
- No Windows 10 runtime/ACL validation or Ubuntu Core i3 hardware benchmark was available.
- No independent APDP/legal review, penetration test, SQLCipher test, production TLS reverse-proxy deployment, or backup/restore/erasure exercise was performed.
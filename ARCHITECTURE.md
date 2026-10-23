# CIDS-Mali Architecture

## Components and data flow

The Flask application is a school-local issuer and administrator. SQLite stores each student and guardian field as a separately AES-256-CBC-encrypted JSON value. The AES master key is a random 32-byte file created once by `init-keys`. The RSA-2048 private key is PKCS#8 PEM protected by PyCA `BestAvailableEncryption` and a password from the environment; the public PEM is portable. POSIX key, database, photo, QR, and card paths are restricted to owner access where private.

Issuance validates the submitted fields and image, normalizes the photo to PNG, and hashes those normalized bytes with SHA-256. It generates one UUID v4 and one UTC issuance timestamp, encrypts only the prescribed student data, and signs canonical UTF-8 JSON containing `version`, `student_id`, `issuer_id`, `encrypted_data`, `issued_at`, and `expires_at`. The final compact QR object uses the specified `v` alias and contains the same timestamp values. Only after artifacts are generated does one SQLite transaction store encrypted fields, consent, and an operator-hashed audit event. A failed database transaction removes the generated artifacts.

Verification checks exact QR keys and types, UUID v4 and timestamps, trusted issuer, RSA PKCS#1 v1.5/SHA-256 signature, validity, optional replay window, local revocation, then decrypts the student data. Signature checking precedes decryption. The Python verifier accepts a locally supplied trust map and revocation set. The browser verifier is a static, self-contained page using Web Crypto AES-CBC and RSA verification; key files and card data are read in-browser and are not uploaded.

## Security decisions

- Passwords use Argon2id. Flask-WTF CSRF, Flask-Login, role checks, login failure throttling, secure cookie defaults, strict input validation, and Jinja autoescaping protect web actions.
- Student-created file paths are never based on uploaded filenames. Files are named only from generated UUIDs and are outside Flask's public static directory.
- Admin erasure deletes student/consent data and associated artifacts, removes the revocation record, and anonymizes related audit references. It does not erase independent backups or already-copied verifier data.
- The specified QR signing envelope is followed exactly. AES-CBC is used as required, not replaced with a different cipher mode or custom construction.
- Key setup is explicit. The app does not generate keys on startup and refuses to start without the AES key and its private-key password.

## STRIDE threat model

| Threat | Example | Controls | Residual risk |
| --- | --- | --- | --- |
| Spoofing | Forged school QR or stolen secretary account | Issuer signature, trusted issuer map, Argon2id, login throttling, role checks | Theft of the issuer private key or a logged-in workstation can mint valid cards. |
| Tampering | QR field edits, malicious form values, path traversal | Signature over canonical fields, strict payload schema, validators, parameterized SQL, UUID-only paths, CSRF | A compromised signing key can issue malicious but correctly signed data. |
| Repudiation | Dispute about issuance or revocation | Timestamped action log and pseudonymized operator hashes | Hashes are not a qualified digital signature; local administrators can alter the SQLite file. |
| Information disclosure | Public access to cards/photos/database or QR plaintext | Field-level encryption, private data directory, authenticated download routes, HTTPS guidance, minimal fields | AES key theft exposes stored fields and QR data. Plaintext is present in authorized application memory and during display/printing. |
| Denial of service | Repeated login attempts or oversized images | Username failure throttling, upload size limit, image validation, bounded SQL queries | No distributed rate limiter or resource-isolation layer; a local-network attacker may still exhaust the host. |
| Elevation of privilege | Secretary uses admin actions | Server-side role checks on each route, CSRF, Argon2id | Compromised admin credentials or host access bypass application controls. |

## Residual risks and mitigations

1. **Private RSA key theft** permits card forgery for that issuer. Keep the key on the school host with restrictive ACLs, use a strong environment-sourced passphrase, restrict administrator accounts, make encrypted offline backups, and rotate promptly after suspected compromise. This prototype does not provide an HSM or national CA.
2. **AES master-key compromise** exposes all field-encrypted database values and enables authorized offline decryption of cards. Keep the file and its backups access-controlled, distribute it only to approved verifier devices, inventory those devices, and treat a lost verifier as a key incident. This prototype does not provide per-device wrapping or remote revocation.
3. **AES-CBC has no intrinsic authentication.** The QR signature authenticates the encrypted QR envelope before decryption, but standalone database fields do not have a separate MAC because the requested format specifies CBC and no field MAC. Filesystem/host protections reduce exposure; production should revise the storage format to an authenticated encryption or encrypt-then-MAC design in a versioned migration.
4. **Offline revocation and time checks are snapshots.** A disconnected device cannot learn a subsequent revocation, and a changed device clock can affect expiry/replay checks. Export authenticated, fresh revocation snapshots immediately before exam sessions and check/secure verifier clocks. The screen should be understood as “valid against this local snapshot,” not a live central status.
5. **QR confidentiality depends on AES-key control.** The QR intentionally carries no clear personal fields, but the decryption key is sensitive. Never distribute it with public QR images or an unprotected verifier bundle.
6. **Consent/erasure operations have organizational dependencies.** This demo records guardian name and consent date but does not implement guardian identity proof, consent-document storage, a formal request workflow, or backup expiry. Schools need APDP-approved policy, guardian procedures, retention schedules, and tested backup deletion.
7. **HTTPS and host deployment are operational.** Flask's development server is for local demonstration only. A LAN deployment needs TLS 1.3 at a maintained reverse proxy, firewall rules, protected OS accounts, patching, backup controls, and security monitoring. No synchronization service is implemented.
8. **SQLite encryption scope is explicit.** Individual sensitive columns are encrypted; SQLite metadata, identifiers, timestamps, status, trusted public keys, and audit events remain readable. SQLCipher is not included in this prototype.

The cryptographic profile is retained to match the project brief. A production protocol change must be versioned and tested for old-card verification rather than silently changing ciphertext or signature canonicalization.
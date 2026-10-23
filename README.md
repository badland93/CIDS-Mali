# CIDS-Mali

Secure, offline-first student identity cards for a single school. This prototype issues signed QR cards from a Flask school-local application and verifies them in Python or in a browser without a network connection.

## Requirements

- Python 3.11 or newer
- Windows 10/11 or Ubuntu 22.04+
- A local machine account that can protect the database and `keys/` directory
- For LAN use: a TLS 1.3 reverse proxy and a school-managed private network

The prototype uses SQLite with AES-256-CBC field encryption. It does not ship SQLCipher, national PKI, central synchronization, NFC, face recognition, or a native Android application. The browser verifier uses Web Crypto and the browser's `BarcodeDetector` where available; pasting QR JSON is the fallback.

## Setup: Ubuntu

```sh
sudo apt install python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and replace `CIDS_SECRET_KEY` and `CIDS_KEY_PASSWORD` with independent, high-entropy values. Keep `.env` private and out of backups that are accessible to non-administrators. `CIDS_COOKIE_SECURE=1` is the production setting and requires HTTPS.

## Setup: Windows

In PowerShell from the project folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` with two independently generated secret values. Restrict `keys`, `data`, and `.env` to the school machine's administrator/service account using Windows ACLs. For example, review the inherited ACLs with `icacls keys` and remove access for other local users before storing real records. `chmod(600)` is applied by the application on POSIX systems; Windows access control is enforced by NTFS ACLs.

## First-time initialization

With `.env` configured and the virtual environment active:

```sh
python -m cids_mali.cli init-keys
python -m cids_mali.cli create-admin director
```

On a fresh database, the first account created is the Director. Only the Director can create Administrator and Secretary accounts, disable/restore them, or remove them from **Comptes administrateurs**. Administrators can issue and manage cards but cannot manage users. Secretaries are restricted to card verification and search.

Cards use one of Mali's official exam categories: DEF, BAC, CAP, BT1, BT2, or IFM. The Director dashboard reports candidate/card counts by category, issuance by administrator, and verification activity. The Director can export these reports and set card validity under **Paramètres système**.

To appoint the owner of an existing installation, use the local console once, naming an existing admin account:

```sh
python -m cids_mali.cli appoint-director director
```

The appointment is allowed only when no Director already exists. Existing user accounts remain enabled during the database migration; the app login and session checks enforce the new active/disabled status thereafter.

`init-keys` creates the encrypted RSA-2048 private key, public key, and random AES-256 master key exactly once. It refuses to overwrite existing keys. Back up both key files securely and test restoration before issuing real cards. Losing the AES master key makes stored student data and issued QR data undecryptable. Never copy the private key to verifier devices.

On Windows, use the same `python -m ...` commands in the activated PowerShell session.

## Run the school application

For local development only, set `CIDS_COOKIE_SECURE=0` in `.env` before starting. Do not use this setting on a school LAN or with real personal data. In production, keep secure cookies enabled and serve Flask behind a TLS 1.3 reverse proxy; do not expose Flask's development server directly to the internet.

```sh
python -m flask --app cids_mali.app:create_app run --host 127.0.0.1 --port 5000
```

Open `http://127.0.0.1:5000`, sign in with the Director account, and create user accounts under **Comptes administrateurs**. Administrators land on candidate/card management; Secretaries land on verification. Issue or edit a card only after recording guardian consent. PDF and PNG downloads are authenticated; photos, QR files, cards, and the database are stored under private `data/`, never Flask's public `static/` tree.

To seed a local demonstration, run:

```sh
python scripts/seed_demo.py
```

The seed data uses synthetic names and generated illustrations, not real student data. It is idempotent. The generated QR payload is stored with private permissions at `data/demo_payload.json` for testing only.

## Offline verification

The browser verifier is `cids_mali/static/offline-verifier.html` with its adjacent JavaScript and `css/offline-verifier.css`. Copy all three assets to an authorized verifier device before the exam. Open the page locally, enter the exact issuer ID, import that issuer's public PEM, the AES master key, and a current revocation-list export. Scan using the camera if the browser supports `BarcodeDetector`, or paste the decoded QR JSON. The page makes no network requests and renders student values with text-only DOM APIs.

The AES master key contains all school records' decryption capability. Only authorized verifier devices may receive it; use encrypted, access-controlled storage and revoke/replace verifier devices after loss. A verifier that is fully offline can only know revocations and trusted keys included in its last update.

The Python verifier accepts decoded QR JSON:

```sh
python -m cids_mali.verifier path/to/qr.json --public-key keys/issuer_public.pem --aes-key keys/aes_master.key --revocations data/revocations.txt --exam-mode
```

The command prints the verification result and, only for a valid card, the requested identity fields. Treat terminal output as personal data.

## Administration and key rotation

```sh
python -m cids_mali.cli export-public-key verifier/issuer_public.pem
python -m cids_mali.cli revoke STUDENT-UUID "Reason for revocation"
python -m cids_mali.cli export-revocations data/revocations.txt
python -m cids_mali.cli erase STUDENT-UUID
python -m cids_mali.cli trust-issuer OLD-ISSUER-ID keys/trusted/OLD-ISSUER-ID.pem
python -m cids_mali.cli rotate-keys --old-issuer-id ML-BKO-001
```

Rotation archives the old public key under `keys/trusted/`; the AES key is not rotated with signing keys. Update `CIDS_ISSUER_ID`, export the new public key, import old keys into verifiers that must accept old cards, and distribute a fresh revocation snapshot. Key distribution and revocation snapshots must be authenticated out of band. A rotation schedule does not replace a documented incident response and tested backup procedure.

Erasure deletes the SQLite student and consent rows, revocation entry, normalized photo, QR image, and card files. It nulls student references in related audit events and replaces the associated operator hashes with a fresh anonymous hash. Existing backups and copies on offline verifier devices require a separate retention/deletion procedure.

## Tests and load test

```sh
python -m pytest -q
```

The suite covers cryptographic behavior, card issuance and offline verification, protected storage, input/path handling, CSRF/session settings, erasure, and local timing targets. See [TEST_REPORT.md](TEST_REPORT.md) for the run results and limits.

For an authenticated Locust run, seed demo data, set `CIDS_LOADTEST_PASSWORD` (at least 12 characters) in the environment, prepare up to 50 unique local users, and point the run at the school app:

```sh
python scripts/prepare_loadtest.py
locust -f tests/locustfile.py --host https://school.example --users 50 --spawn-rate 10 --run-time 5m
```

Use a test database and test-only credentials. The app's production secure-cookie setting requires HTTPS. The load-test accounts are named `load-001` through `load-050` and should be removed after testing.

## Project map

- `cids_mali/crypto_utils.py`: AES-CBC/PKCS7, RSA signatures, key files, hashes
- `cids_mali/models.py`: SQLite access, encrypted fields, consent, users, audit and revocation
- `cids_mali/qr_generator.py`: input validation, photo normalization, signed QR, PNG and PDF
- `cids_mali/verifier.py`: importable offline verifier and CLI
- `cids_mali/admin.py`, `cids_mali/cli.py`: key setup/rotation, user/card administration
- `cids_mali/app.py`, `templates/`, `static/`: local web workflows and browser verifier
- `tests/`: unit, flow, security and Locust coverage
- `ARCHITECTURE.md`: flow, threat model and residual risks

This is a security-minded prototype, not a legal compliance certification or a substitute for an APDP review, operational security assessment, or school-specific consent/retention policy.

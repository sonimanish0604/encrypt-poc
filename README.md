📘 DNC Preference Encryption PoC
Field-Level Encryption-at-Rest using Envelope Encryption, KEK Rotation, Vault Transit, FastAPI, and MySQL (Dockerized)
🚀 Overview

This Proof of Concept demonstrates secure handling of customer PII submitted through a Do Not Contact (DNC) preference form.
The solution applies field-level encryption using AES-256-GCM, Data Encryption Keys (DEKs), and Key Encryption Keys (KEKs) stored and rotated using HashiCorp Vault Transit, simulating a cloud KMS.

The PoC is fully containerized using Docker Compose, runs locally with zero cloud cost, and demonstrates real-world security architecture patterns used in Telecom, Banking, and Healthcare industries.

🎯 Business Need

Regulated businesses (Telecom, Banking, Health, Insurance) allow customers to manage their DNC preferences to comply with privacy regulations.
The form captures PII:

First Name

Middle Name

Last Name

Phone Number

Email Address

Phone DNC Preference (ON/OFF Toggle)

Email DNC Preference (ON/OFF Toggle)

Since PII is involved, the system must:

Encrypt data before storing in the database

Manage cryptographic keys securely

Support KEK rotation without re-encrypting stored data

Allow ETL/analytics systems to decrypt values safely

This PoC demonstrates these capabilities in a clean, minimal, reproducible environment.

🏛 High-Level Architecture
Browser → FastAPI → Vault Transit (KEK) → MySQL → ETL → Vault Transit (KEK)

| Component                 | Purpose                                                     |
| ------------------------- | ----------------------------------------------------------- |
| **Webform / REST Client** | Submits DNC preferences                                     |
| **FastAPI Service**       | Validates input, unwraps DEK, encrypts PII, writes to MySQL |
| **Vault Transit Engine**  | Stores KEK; wraps/unwraps DEKs; supports KEK rotation       |
| **MySQL 8**               | Stores ciphertext + wrapped DEKs                            |
| **ETL Script**            | Reads encrypted rows, uses KEK to unwrap DEK, decrypts data |

Encryption Model

API does AES-256-GCM encryption for each PII field.

DEK (Data Encryption Key) encrypts PII.

KEK (Master Key) in Vault Transit wraps the DEK.

KEK rotation is done using Vault Transit key versioning — no re-encryption of data required.

🗂 Repository Structure

encryption-poc/
├─ docker-compose.yml
├─ README.md
├─ diagrams/
│    ├─ architecture.puml
│    ├─ submit_sequence.puml
│    ├─ etl_sequence.puml
│    └─ modules.puml
└─ app/
     ├─ main.py              # FastAPI application
     ├─ crypto_utils.py      # AES-GCM + Vault wrap/unwrap helpers
     ├─ db.py                # MySQL schema + connection
     ├─ etl.py               # ETL decrypt script
     ├─ config.py            # Environment variables
     ├─ requirements.txt
     └─ Dockerfile

If deployers want to generate diagram images, a PlantUML GitHub Action or local renderer may be used.

🔧 Prerequisites

Docker

Docker Compose
(No Python or Vault installation is required — everything runs in containers.)

▶️ How to Run the PoC
1. **Clone & start containers**

```bash
git clone <repo-url>
cd encrypt-poc
docker compose up --build
```

This launches:

- `enc_vault` (Vault dev mode, root token `root`, http://localhost:8200)
- `enc_mysql` (MySQL 8.0 with schema `enc_poc`)
- `enc_api` (FastAPI service on http://localhost:8000)
- `enc_adminer` (Adminer UI on http://localhost:8080)

On startup the API waits for Vault/MySQL, mounts the transit engine, creates the `pii-master` KEK if missing, and seeds an active wrapped DEK in MySQL.

2. **Submit DNC preferences (Swagger or curl)**

- Swagger UI: http://localhost:8000/docs → `POST /submit` → “Try it out”.
- Curl:

```bash
curl -X POST http://localhost:8000/submit \
  -H "Content-Type: application/json" \
  -d '{
        "first_name": "Alice",
        "middle_name": "M",
        "last_name": "Doe",
        "phone": "+15551234567",
        "email": "alice@example.com",
        "phone_dnc": true,
        "email_dnc": false
      }'
```

Response: `{"status":"ok"}`.

3. **Inspect encrypted rows**

- Adminer: http://localhost:8080 (Server `mysql`, user `root`, password `rootpassword`, database `enc_poc`). Browse the `contact_form` table to see ciphertext blobs plus wrapped DEK reference.
- CLI:

```bash
docker exec -it enc_mysql mysql -uroot -prootpassword enc_poc \
  -e "SELECT id, key_id, HEX(first_name_enc) FROM contact_form;"
```

4. **Run the ETL decrypt demo**

```bash
docker compose run --rm api python etl.py
```

Sample output:

```
Row 1:
  First Name: Alice
  Middle Name: M
  Last Name: Doe
  Phone: +15551234567
  Email: alice@example.com
  Flags: phone_dnc=True email_dnc=False
```

ETL joins each row on `encryption_keys`, asks Vault to unwrap the DEK, then performs AES-GCM decrypt—no plaintext keys or data ever touch MySQL.

🔐 Key Management & KEK Rotation
What is rotated?

✔ Key Encryption Key (KEK) in Vault
✖ Data Encryption Key (DEK) (not rotated in this PoC)

Why KEK rotation?

Because rotating the KEK:

Does not require decrypting or rewriting database rows

Is low-risk and low-cost

Is the industry standard approach (banks, telecom, healthcare)

How to rotate the KEK (Vault Transit)

In another terminal:

docker exec -it enc_vault sh
vault write -f transit/keys/pii-master/rotate

Vault increments the key version internally.

What happens after rotation?

Existing wrapped DEKs continue to decrypt correctly

New DEK wrapping uses the new KEK version

No re-encryption of PII or DEKs is needed

This mirrors AWS KMS, Azure Key Vault, and GCP KMS behaviors.
🧩 How This Demonstrates Real Enterprise Concepts

This PoC implements:

✔ Envelope Encryption

DEK encrypts data

KEK wraps DEK

KEK never leaves Vault

✔ KEK Rotation

Zero impact on data

No re-encryption needed

Industry-aligned practice

✔ Field-Level Encryption

Protects individual columns (PII only)

✔ Separation of Duties

API can encrypt

ETL can decrypt

Database cannot access keys

✔ Complete Local Dev Environment

Easily shareable on GitHub

Perfect for LinkedIn content and demonstrating hands-on skills

🛣 Future Enhancements

You may enhance the PoC later with:

Tokenization (e.g., for phone/email)

DEK rotation (full re-encryption workflow)

API Gateway with rate limiting

mTLS between API and Vault

JWT-based authentication for API

Structured logging + audit trails

Integration with AWS KMS or GCP KMS instead of Vault

🤝 Author

Built by Manish Soni
Security, Privacy & Solutions Architecture enthusiast

If you like this PoC, feel free to ⭐ the repo and follow for more projects!

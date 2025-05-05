# Cloud Encryption & Key Management System (CEKMS)

### **User Guide — Install · Operate · Demo**

---

## 1  Prerequisites

| Component           | Min Version    | Notes                            |
| ------------------- | -------------- | -------------------------------- |
| Python              | **3.10**       | Windows / macOS / Linux          |
| pip                 | 22             | Ships with Python installer      |
| Streamlit           | 1.32           | Installed via _requirements.txt_ |
| OpenSSL             | System default | Bundled on most OSes             |
| Docker _(optional)_ | 24 +           | One‑command sandbox deployment   |

> **Hardware**  Dual‑core CPU · 4 GB RAM · ≈ 200 MB disk  
> **URL**       Dashboard served at **http://localhost:8501** by default.

---

## 2  Installation Options

### 2.1 Local Python

```bash
# Clone repository
$ git clone https://github.com/your‑org/cekms.git && cd cekms

# (Recommended) create virtual‑env
$ python -m venv .venv
$ source .venv/bin/activate              # Windows: .venv\Scripts\activate

# Install dependencies
$ pip install -r requirements.txt

# Launch Streamlit app
$ streamlit run app.py
```

### 2.2 Docker

```bash
# Build once
$ docker build -t cekms .

# Run container
$ docker run -p 8501:8501 cekms
```

Both methods create an **auto‑initialised `data/keys.db`** file holding keys and audit logs.

---

## 3  Folder Layout

```
cekms/
├─ app.py              # Streamlit entry‑point
├─ keys.db        # SQLite database (auto‑created)

```

---

## 4  Operating the Dashboard

| Sidebar Icon | Page                  | Core Functions                                                                    |
| ------------ | --------------------- | --------------------------------------------------------------------------------- |
| 🏠           | **Home**              | Overview & links                                                                  |
| 🔑           | **Key Management**    | Generate · Rotate · Revoke · Delete keys; view status badges                      |
| 🔒           | **Encrypt / Decrypt** | Secure **text** & **files ≤ 20 MB** (PDF, images, video, Office, ZIP, any binary) |
| 🤖           | **ML Insights**       | Anomaly alerts & rotation forecasts                                               |
| 📖           | **Documentation**     | Inline help & troubleshooting                                                     |

### 4.1 Key Creation

1. Open **Key Management → Generate New Key Pair**.
2. Accept default name or enter custom.
3. Click **Generate Key** → row appears with status **Active**.

### 4.2 Text Encryption / Decryption

1. Go to **Encrypt/Decrypt** & select a key.
2. Pick **Encrypt Text**, enter plaintext → **Encrypt ▶**.
3. Copy Base64 ciphertext.  
   _To decrypt_, paste ciphertext, choose **Decrypt Text** → **Decrypt ▶**.

### 4.3 File Encryption / Decryption

1. In **Encrypt File**, select tab (PDF / Image / Video / Document / Zip / Other).
2. Upload file ≤ 20 MB → **Encrypt ▶** → download `filename.ext.enc`.
3. To decrypt, upload `.enc` under **Decrypt File** → **Decrypt ▶**; original file downloads with its real extension.

### 4.4 Lifecycle Controls

- **Rotate** — new AES component; old ciphertext breaks (forward secrecy).
- **Revoke** — blocks all future use; badge turns red.
- **Delete** — removes key material; audit log persists.  
  _Confirmation dialogs guard destructive ops._

### 4.5 Theme Toggle

Sidebar **🎨 Theme** instantly switches **Light ⇄ Dark**. Dark mode forces pure‑white text on charcoal background for high contrast.

---

## 5  Demonstration Script (≈ 8 min)

| Min | Action                | Talking Points                               |
| --- | --------------------- | -------------------------------------------- |
| 1   | Introduce Home        | Cloud exposure → need client‑side keys       |
| 1   | Generate key          | RSA‑4096/AES‑256 · 90‑day expiry metadata    |
| 2   | Encrypt & decrypt PDF | Live speed (< 500 ms); filename restored     |
| 1   | Rotate key            | Decrypt fails ⇒ forward secrecy demo         |
| 1   | Trigger anomaly       | Rapid encrypt loop → red **Anomalous** badge |
| 1   | View forecast         | Line chart shows proactive rotation date     |
| 1   | Theme + export logs   | Accessibility & compliance evidence          |

---

## 6  Troubleshooting FAQ

| Symptom               | Likely Cause            | Fix                                                        |
| --------------------- | ----------------------- | ---------------------------------------------------------- |
| **“Max 20 MB” error** | File exceeds size cap   | Compress or split file                                     |
| Duplicate key name    | Label collision         | Append timestamp or delete old key                         |
| Decryption blocked    | Key revoked / expired   | Un‑revoke, extend expiry, or create new key                |
| Port 8501 busy        | Another service running | `streamlit run app.py --server.port 8502`                  |
| Docker image large    | Using default tag       | Build multi‑stage: `docker build --target prod -t cekms .` |

---

## 7  Uninstall / Clean‑up

*Local install* — delete project folder (and virtual‑env). Secure‑wipe `data/keys.db` if keys must be destroyed.  
*Docker* — `docker rm $(docker ps -a -q -f ancestor=cekms)` then `docker rmi cekms`.

---

© 2025  Cloud Encryption & Key Management System — MIT Licence

import streamlit as st
import sqlite3
import os
import base64
import json
import struct
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LinearRegression

# ─── Streamlit Page Config ─────────────────────────────────────────────────────
st.set_page_config(page_title="Cloud Encryption & Key Management", layout="wide")

# ─── Constants ─────────────────────────────────────────────────────────────────
DB_PATH = "keys.db"
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
EXPIRATION_DAYS = 90

# ─── Database Helpers ──────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT UNIQUE NOT NULL,
            private_key   BLOB NOT NULL,
            public_key    BLOB NOT NULL,
            aes_key       BLOB NOT NULL,
            created_at    TEXT NOT NULL,
            expires_at    TEXT NOT NULL,
            revoked       INTEGER DEFAULT 0,
            rotations     INTEGER DEFAULT 0
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id    INTEGER NOT NULL,
            action    TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

@st.cache_resource
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def log_action(key_id: int, action: str):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO logs (key_id, action, timestamp) VALUES (?, ?, ?)",
        (key_id, action, datetime.utcnow().isoformat())
    )
    conn.commit()

# ─── Cryptography Helpers ─────────────────────────────────────────────────────
def generate_rsa_keys():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    return priv, priv.public_key()

def generate_aes_key():
    return os.urandom(32)

def serialize_private_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def serialize_public_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def hybrid_encrypt(plaintext: bytes, public_pem: bytes, aes_key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    ciphertext = cipher.encryptor().update(plaintext) + cipher.encryptor().finalize()
    pub = serialization.load_pem_public_key(public_pem, backend=default_backend())
    enc_key = pub.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return iv, enc_key, ciphertext

def hybrid_decrypt(iv: bytes, enc_key: bytes, ciphertext: bytes, private_pem: bytes):
    priv = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
    aes_key = priv.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    return cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()

# ─── Machine Learning Helpers ─────────────────────────────────────────────────
@st.cache_data
def train_anomaly_detector():
    conn = get_db_connection()
    df = pd.read_sql("SELECT key_id, COUNT(*) AS count FROM logs GROUP BY key_id", conn)
    if df.empty:
        return None
    model = IsolationForest(contamination=0.1)
    model.fit(df[['count']])
    return model, df

@st.cache_data
def train_rotation_predictor():
    conn = get_db_connection()
    df = pd.read_sql("SELECT key_id, timestamp FROM logs ORDER BY timestamp", conn)
    if df.empty:
        return None
    usage = df.groupby('key_id').size().reset_index(name='count')
    X = usage[['key_id']].values
    y = usage['count'].values
    model = LinearRegression()
    model.fit(X, y)
    return model

# ─── Sidebar Navigation & Theme ────────────────────────────────────────────────
st.sidebar.markdown("## 📂 Navigation")
page = st.sidebar.radio(
    "",
    ["🏠 Home", "🔑 Key Management", "🔒 Encrypt/Decrypt", "🤖 ML Insights", "📖 Documentation"],
    index=0
)
page = page.split(" ", 1)[1]

# Theme selection
theme = st.sidebar.selectbox("🎨 Theme", ["Light", "Dark"])
if theme == "Dark":
    st.markdown("""
    <style>
      /* Backgrounds */
      .stApp, .css-1d391kg, .css-1outpf7, .css-18nj8uf, .css-1lcbmhc { background-color: #0E1117 !important; }
      .stSidebar, .css-1d391kg, .css-1outpf7, .css-1lcbmhc { background-color: #131722 !important; }

      /* Text */
      .stApp *, .stSidebar * {
        color: #FAFAFA !important;
      }

      /* Buttons */
      .stButton>button {
        background-color: #1E8BC3 !important;
        color: #FAFAFA !important;
      }

      /* Inputs */
      input, textarea {
        background-color: #1A1A1A !important;
        color: #FAFAFA !important;
      }

      /* Tables */
      .ag-theme-streamlit {
        background-color: #1A1A1A !important;
        color: #FAFAFA !important;
      }
    </style>
    """, unsafe_allow_html=True)

# ─── Streamlit UI ─────────────────────────────────────────────────────────────
def main():
    init_db()
    st.title("🔐 Cloud Encryption & Key Management System")
    st.markdown("---")

    # Home
    if page == "Home":
        st.header("🏠 Home")
        st.write("""
        **Welcome!**  
        Use the sidebar to navigate:  
        - **Key Management**: Create, rotate, revoke, delete keys.  
        - **Encrypt/Decrypt**: Secure text & files.  
        - **ML Insights**: Detect anomalies & forecast rotations.  
        - **Documentation**: This guide.
        """)

    # Key Management
    elif page == "Key Management":
        st.header("🔑 Key Management")
        conn = get_db_connection()
        c = conn.cursor()

        with st.expander("➕ Generate New Key Pair", expanded=True):
            name = st.text_input("Key Name", value=f"Key_{datetime.utcnow():%Y%m%d_%H%M%S}")
            if st.button("Generate Key"):
                if not name.strip():
                    st.error("Key name is required.")
                else:
                    try:
                        priv, pub = generate_rsa_keys()
                        aes = generate_aes_key()
                        now = datetime.utcnow()
                        exp = now + timedelta(days=EXPIRATION_DAYS)
                        c.execute("""
                            INSERT INTO keys 
                              (name, private_key, public_key, aes_key, created_at, expires_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            name.strip(),
                            serialize_private_key(priv),
                            serialize_public_key(pub),
                            aes,
                            now.isoformat(),
                            exp.isoformat()
                        ))
                        conn.commit()
                        st.success(f"Key '{name}' created.")
                    except sqlite3.IntegrityError:
                        st.error("Key name already exists.")

        st.subheader("Existing Keys")
        keys_df = pd.read_sql(
            "SELECT id, name, created_at, expires_at, revoked, rotations FROM keys",
            conn
        )
        st.dataframe(keys_df, use_container_width=True)

        if not keys_df.empty:
            key_id = st.selectbox("Select Key ID", keys_df["id"])
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("Revoke Key"):
                    conn.execute("UPDATE keys SET revoked=1 WHERE id=?", (key_id,))
                    conn.commit()
                    log_action(key_id, "revoke")
                    st.warning("Key revoked.")
            with col2:
                if st.button("Rotate Key"):
                    new_aes = generate_aes_key()
                    conn.execute(
                        "UPDATE keys SET aes_key=?, rotations=rotations+1 WHERE id=?",
                        (new_aes, key_id)
                    )
                    conn.commit()
                    log_action(key_id, "rotate")
                    st.success("Key AES portion rotated.")
            with col3:
                if st.button("Delete Key"):
                    conn.execute("DELETE FROM keys WHERE id=?", (key_id,))
                    conn.commit()
                    st.error("Key deleted.")

    # Encrypt/Decrypt
    elif page == "Encrypt/Decrypt":
        st.header("🔒 Encrypt / Decrypt")
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT id, name, public_key, private_key, aes_key, expires_at 
            FROM keys WHERE revoked=0
        """).fetchall()
        valid = [r for r in rows if datetime.fromisoformat(r["expires_at"]) > datetime.utcnow()]
        if not valid:
            st.info("No active keys available.")
            return

        key_map = {r["name"]: r for r in valid}
        key_choice = st.selectbox("Select Key", list(key_map.keys()))
        key = key_map[key_choice]
        mode = st.radio("Mode", ["Encrypt Text", "Decrypt Text", "Encrypt File", "Decrypt File"])
        st.markdown("---")

        if "Text" in mode:
            txt = st.text_area("Input Text", help="Plain text or Base64")
            if st.button(f"{mode} ▶"):
                if not txt.strip():
                    st.error("Input required.")
                else:
                    try:
                        if mode == "Encrypt Text":
                            iv, ek, ct = hybrid_encrypt(txt.encode(), key["public_key"], key["aes_key"])
                            out = base64.b64encode(iv + ek + ct).decode()
                            st.code(out)
                        else:
                            raw = base64.b64decode(txt.strip())
                            iv, ek, ct = raw[:16], raw[16:528], raw[528:]
                            plain = hybrid_decrypt(iv, ek, ct, key["private_key"])
                            st.code(plain.decode())
                        log_action(key["id"], mode.lower().replace(" ", "_"))
                    except Exception as e:
                        st.error(e)
        else:
            if mode == "Encrypt File":
                tab_labels = ["PDF", "Image", "Video", "Document", "Zip", "Other"]
                ext_map = {
                    "PDF": ["pdf"], "Image": ["png","jpg","jpeg","gif"],
                    "Video": ["mp4","mov","avi","mkv"], "Document": ["doc","docx","xls","xlsx","ppt","pptx","txt","rtf"],
                    "Zip": ["zip","rar","7z","tar","gz"], "Other": None
                }
                tabs = st.tabs(tab_labels)
                data_bytes, filename = None, None
                for lbl, tab in zip(tab_labels, tabs):
                    with tab:
                        upl = st.file_uploader(f"Upload {lbl}", type=ext_map[lbl], key=lbl)
                        if upl:
                            if upl.size > MAX_FILE_SIZE:
                                st.error("Max 20 MB."); return
                            data_bytes = upl.read()
                            filename = upl.name
                if data_bytes and st.button("Encrypt ▶"):
                    try:
                        meta = json.dumps({"filename": filename}).encode()
                        hdr = struct.pack(">I", len(meta)) + meta
                        iv, ek, ct = hybrid_encrypt(data_bytes, key["public_key"], key["aes_key"])
                        blob = hdr + iv + ek + ct
                        st.download_button("Download Encrypted", blob, f"{filename}.enc")
                        log_action(key["id"], "encrypt_file")
                    except Exception as e:
                        st.error(e)
            else:
                upl = st.file_uploader("Upload .enc File", type=["enc"])
                if upl and st.button("Decrypt ▶"):
                    if upl.size > MAX_FILE_SIZE:
                        st.error("Max 20 MB."); return
                    raw = upl.read()
                    try:
                        hdr_len = struct.unpack(">I", raw[:4])[0]
                        meta = json.loads(raw[4:4+hdr_len].decode())
                        orig = meta.get("filename", "decrypted_file")
                        offset = 4 + hdr_len
                        iv, ek, ct = raw[offset:offset+16], raw[offset+16:offset+528], raw[offset+528:]
                        plain = hybrid_decrypt(iv, ek, ct, key["private_key"])
                        st.download_button("Download Decrypted", plain, orig)
                        log_action(key["id"], "decrypt_file")
                    except Exception as e:
                        st.error(e)

    # ML Insights
    elif page == "ML Insights":
        st.header("🤖 ML Insights")
        conn = get_db_connection()

        det = train_anomaly_detector()
        if det:
            model, df = det
            df["anomaly"] = model.predict(df[["count"]])
            st.subheader("Anomalous Usage")
            st.dataframe(df[df["anomaly"] == -1], use_container_width=True)
            fig, ax = plt.subplots()
            ax.bar(df['key_id'].astype(str), df['count'])
            ax.set_xlabel('Key ID')
            ax.set_ylabel('Usage Count')
            ax.set_title('Total Usage per Key')
            st.pyplot(fig)
        else:
            st.info("Insufficient logs for anomalies.")

        pred = train_rotation_predictor()
        if pred:
            st.subheader("Rotation Forecast")
            usage = pd.read_sql("SELECT key_id, COUNT(*) AS count FROM logs GROUP BY key_id", conn)
            preds = pred.predict(usage[["key_id"]])
            forecast = pd.DataFrame({
                "key_id": usage["key_id"],
                "actual": usage["count"],
                "predicted": preds
            })
            st.dataframe(forecast, use_container_width=True)
            fig2, ax2 = plt.subplots()
            ax2.plot(forecast['key_id'], forecast['actual'], marker='o', label='Actual')
            ax2.plot(forecast['key_id'], forecast['predicted'], marker='x', linestyle='--', label='Predicted')
            ax2.set_xlabel('Key ID')
            ax2.set_ylabel('Usage Count')
            ax2.set_title('Actual vs Predicted Usage')
            ax2.legend()
            st.pyplot(fig2)
        else:
            st.info("Insufficient logs for forecasting.")

    # Documentation
    else:
        st.header("📖 Documentation")
        st.markdown("""
        **Navigation**  
        Use the sidebar buttons to switch between pages.

        **Home**: Overview & quick start.  
        **Key Management**: Create, rotate, revoke, delete keys.  
        **Encrypt/Decrypt**: Encrypt/decrypt text & files.  
        **ML Insights**: Visualize usage patterns, detect anomalies, forecast rotations.  
        **Documentation**: This guide.
        """)

if __name__ == "__main__":
    main()

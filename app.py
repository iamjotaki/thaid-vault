import os
import json
import uuid
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Header, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Resilient persistent storage resolution:
# If /app/data volume exists, use /app/data/vault.db. If not yet seeded, copy baseline vault.db into it.
DATA_DIR = os.path.join(BASE_DIR, "data")
if os.path.isdir(DATA_DIR):
    DATA_DB = os.path.join(DATA_DIR, "vault.db")
    BASE_DB = os.path.join(BASE_DIR, "vault.db")
    if not os.path.exists(DATA_DB) and os.path.exists(BASE_DB):
        import shutil
        shutil.copy2(BASE_DB, DATA_DB)
    DB_PATH = DATA_DB if os.path.exists(DATA_DB) else BASE_DB
else:
    DB_PATH = os.path.join(BASE_DIR, "vault.db")

app = FastAPI(title="ThaiD Personal Vault", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active Sessions: token -> expires_at
active_sessions: Dict[str, datetime] = {}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def get_or_create_encryption_key(conn) -> bytes:
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'encryption_key'")
    row = cursor.fetchone()
    if row:
        return row["value"].encode("utf-8")
    new_key = Fernet.generate_key().decode("utf-8")
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('encryption_key', ?)", (new_key,))
    conn.commit()
    return new_key.encode("utf-8")

def encrypt_secret(plain_text: str, conn) -> str:
    if not plain_text:
        return ""
    key = get_or_create_encryption_key(conn)
    f = Fernet(key)
    return f.encrypt(plain_text.encode("utf-8")).decode("utf-8")

def decrypt_secret(cipher_text: str, conn) -> str:
    if not cipher_text:
        return ""
    try:
        key = get_or_create_encryption_key(conn)
        f = Fernet(key)
        return f.decrypt(cipher_text.encode("utf-8")).decode("utf-8")
    except Exception:
        return cipher_text

def hash_pin(pin: str, salt: str) -> str:
    return hashlib.sha256((salt + pin).encode("utf-8")).hexdigest()

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT UNIQUE,
        name TEXT NOT NULL,
        icon TEXT DEFAULT 'folder',
        color TEXT DEFAULT '#0071e3',
        description TEXT,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        username TEXT,
        password_encrypted TEXT,
        url TEXT,
        notes TEXT,
        expires_at TEXT,
        is_favorite INTEGER DEFAULT 0,
        custom_fields TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories (id) ON DELETE CASCADE
    );
    """)

    # Check Master PIN
    cursor.execute("SELECT value FROM settings WHERE key = 'master_pin_hash'")
    if not cursor.fetchone():
        salt = secrets.token_hex(16)
        default_pin = "2026"
        hashed = hash_pin(default_pin, salt)
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('master_pin_salt', ?)", (salt,))
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('master_pin_hash', ?)", (hashed,))
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('vault_title', 'ThaiD Vault')")

    # Seed Default Categories
    cursor.execute("SELECT COUNT(*) as count FROM categories")
    if cursor.fetchone()["count"] == 0:
        default_categories = [
            ("domains", "โดเมน & DNS", "language", "#0071e3", "โดเมนเว็บไซต์ ผู้ให้บริการจดโดเมน และการตั้งค่า DNS", 1),
            ("ai", "บัญชี AI & API Keys", "smart_toy", "#e85a2d", "บัญชี Gemini Pro, Claude, OpenAI และ API Keys", 2),
            ("hosting", "เซิร์ฟเวอร์ & โฮสติ้ง", "cloud", "#8b5cf6", "Oracle Cloud, Coolify, SSH, IP และพอร์ต", 3),
            ("web", "บัญชีเว็บไซต์ทั่วไป", "key", "#10b981", "บัญชีเว็บ พอร์ทัลสมาชิก อีเมล และโซเชียลมีเดีย", 4),
            ("billing", "การชำระเงิน & บิลรายเดือน", "credit_card", "#f59e0b", "บริการแบบ Subscription วันตัดรอบ และบัตรที่ใช้", 5),
        ]
        for cat in default_categories:
            cursor.execute("""
            INSERT INTO categories (slug, name, icon, color, description, sort_order)
            VALUES (?, ?, ?, ?, ?, ?)
            """, cat)

        # Seed initial existing ecosystem items
        cursor.execute("SELECT id FROM categories WHERE slug = 'domains'")
        cat_domains = cursor.fetchone()["id"]
        cursor.execute("SELECT id FROM categories WHERE slug = 'hosting'")
        cat_hosting = cursor.fetchone()["id"]
        cursor.execute("SELECT id FROM categories WHERE slug = 'ai'")
        cat_ai = cursor.fetchone()["id"]

        items_to_seed = [
            (
                cat_domains,
                "โดเมนหลัก ThaiD.online (Spaceship)",
                "iamjotaki@gmail.com",
                encrypt_secret("", conn),
                "https://www.spaceship.com",
                "จดโดเมน thaid.online ชี้ Nameservers: launch1.spaceship.net, launch2.spaceship.net พร้อม Wildcard *.thaid.online ชี้ไปที่ Oracle Cloud IP 129.221.170.225",
                "2027-10-25",
                1
            ),
            (
                cat_hosting,
                "Oracle Cloud Infrastructure (OCI Always Free)",
                "iamjotaki@gmail.com",
                encrypt_secret("", conn),
                "https://cloud.oracle.com",
                "VM yayni-node2-12gb (Public IP: 129.221.170.225 / Private IP: 10.0.0.241) Always Free Ampere A1 (4 OCPU, 12 GB RAM), SSH User: ubuntu, Key file: C:\\NV\\oracle_key.pem",
                "",
                1
            ),
            (
                cat_hosting,
                "Coolify Control Panel (Server Dashboard)",
                "iamjotaki@gmail.com",
                encrypt_secret("", conn),
                "http://thaid.online:8000",
                "แผงควบคุมระบบคลาวด์และคอนเทนเนอร์ ThaiD Ecosystem ควบคุม thaid.online, novel.thaid.online, social.thaid.online พอร์ต 8000",
                "",
                1
            ),
            (
                cat_ai,
                "Gemini Pro & Google Cloud Console",
                "iamjotaki@gmail.com",
                encrypt_secret("", conn),
                "https://aistudio.google.com",
                "บัญชี Google AI Studio และ Gemini Pro API สำหรับระบบแต่งนิยาย ReadAWrite Pro Studio และการประมวลผลข้อความ",
                "",
                1
            ),
        ]

        for item in items_to_seed:
            cursor.execute("""
            INSERT INTO vault_items (category_id, title, username, password_encrypted, url, notes, expires_at, is_favorite)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, item)

    conn.commit()
    conn.close()

init_db()

# --- Auth Dependencies ---
def check_auth(x_vault_token: Optional[str] = Header(None)):
    if not x_vault_token or x_vault_token not in active_sessions:
        raise HTTPException(status_code=401, detail="Session expired or locked. Please enter PIN.")
    if datetime.now() > active_sessions[x_vault_token]:
        del active_sessions[x_vault_token]
        raise HTTPException(status_code=401, detail="Session expired. Please enter PIN.")
    # Slide session expiration by 30 mins
    active_sessions[x_vault_token] = datetime.now() + timedelta(minutes=30)
    return True

# --- Models ---
class VerifyPinRequest(BaseModel):
    pin: str

class SetPinRequest(BaseModel):
    current_pin: str
    new_pin: str

class CategoryCreate(BaseModel):
    name: str
    icon: Optional[str] = "folder"
    color: Optional[str] = "#0071e3"
    description: Optional[str] = ""
    sort_order: Optional[int] = 0

class CategoryUpdate(BaseModel):
    name: str
    icon: Optional[str] = "folder"
    color: Optional[str] = "#0071e3"
    description: Optional[str] = ""
    sort_order: Optional[int] = 0

class VaultItemCreate(BaseModel):
    category_id: int
    title: str
    username: Optional[str] = ""
    password: Optional[str] = ""
    url: Optional[str] = ""
    notes: Optional[str] = ""
    expires_at: Optional[str] = ""
    is_favorite: Optional[int] = 0

class VaultItemUpdate(BaseModel):
    category_id: int
    title: str
    username: Optional[str] = ""
    password: Optional[str] = ""
    url: Optional[str] = ""
    notes: Optional[str] = ""
    expires_at: Optional[str] = ""
    is_favorite: Optional[int] = 0

# --- API Endpoints ---

@app.get("/api/auth/status")
def auth_status(x_vault_token: Optional[str] = Header(None)):
    is_unlocked = False
    if x_vault_token and x_vault_token in active_sessions:
        if datetime.now() <= active_sessions[x_vault_token]:
            is_unlocked = True
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'vault_title'")
    row = cursor.fetchone()
    title = row["value"] if row else "ThaiD Vault"
    conn.close()
    return {"unlocked": is_unlocked, "vault_title": title}

@app.post("/api/auth/verify-pin")
def verify_pin(data: VerifyPinRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'master_pin_salt'")
    salt = cursor.fetchone()["value"]
    cursor.execute("SELECT value FROM settings WHERE key = 'master_pin_hash'")
    stored_hash = cursor.fetchone()["value"]
    conn.close()

    if hash_pin(data.pin, salt) != stored_hash:
        raise HTTPException(status_code=400, detail="รหัส PIN ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง")

    token = secrets.token_hex(24)
    active_sessions[token] = datetime.now() + timedelta(minutes=30)
    return {"token": token, "message": "ปลดล็อกสำเร็จ"}

@app.post("/api/auth/set-pin")
def set_pin(data: SetPinRequest, auth: bool = Depends(check_auth)):
    if len(data.new_pin) < 4:
        raise HTTPException(status_code=400, detail="รหัส PIN ต้องมีความยาวอย่างน้อย 4 หลัก")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'master_pin_salt'")
    salt = cursor.fetchone()["value"]
    cursor.execute("SELECT value FROM settings WHERE key = 'master_pin_hash'")
    stored_hash = cursor.fetchone()["value"]

    if hash_pin(data.current_pin, salt) != stored_hash:
        conn.close()
        raise HTTPException(status_code=400, detail="รหัส PIN ปัจจุบันไม่ถูกต้อง")

    new_salt = secrets.token_hex(16)
    new_hash = hash_pin(data.new_pin, new_salt)
    cursor.execute("UPDATE settings SET value = ? WHERE key = 'master_pin_salt'", (new_salt,))
    cursor.execute("UPDATE settings SET value = ? WHERE key = 'master_pin_hash'", (new_hash,))
    conn.commit()
    conn.close()
    return {"message": "เปลี่ยนรหัส PIN สำเร็จเรียบร้อยแล้ว"}

@app.post("/api/auth/lock")
def lock_vault(x_vault_token: Optional[str] = Header(None)):
    if x_vault_token and x_vault_token in active_sessions:
        del active_sessions[x_vault_token]
    return {"message": "ล็อกคลังข้อมูลเรียบร้อยแล้ว"}

# --- Category CRUD ---

@app.get("/api/categories")
def list_categories(auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT c.*, COUNT(v.id) as item_count 
    FROM categories c 
    LEFT JOIN vault_items v ON c.id = v.category_id 
    GROUP BY c.id 
    ORDER BY c.sort_order ASC, c.id ASC
    """)
    rows = cursor.fetchall()
    categories = [dict(row) for row in rows]
    conn.close()
    return categories

@app.post("/api/categories")
def create_category(cat: CategoryCreate, auth: bool = Depends(check_auth)):
    slug = f"cat_{secrets.token_hex(4)}"
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
        INSERT INTO categories (slug, name, icon, color, description, sort_order)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (slug, cat.name.strip(), cat.icon.strip(), cat.color.strip(), cat.description.strip(), cat.sort_order))
        conn.commit()
        new_id = cursor.lastrowid
        cursor.execute("SELECT *, 0 as item_count FROM categories WHERE id = ?", (new_id,))
        created = dict(cursor.fetchone())
        conn.close()
        return created
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"ไม่สามารถเพิ่มหมวดหมู่ได้: {str(e)}")

@app.put("/api/categories/{category_id}")
def update_category(category_id: int, cat: CategoryUpdate, auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM categories WHERE id = ?", (category_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="ไม่พบหมวดหมู่นี้")
    cursor.execute("""
    UPDATE categories 
    SET name = ?, icon = ?, color = ?, description = ?, sort_order = ?
    WHERE id = ?
    """, (cat.name.strip(), cat.icon.strip(), cat.color.strip(), cat.description.strip(), cat.sort_order, category_id))
    conn.commit()
    cursor.execute("""
    SELECT c.*, COUNT(v.id) as item_count 
    FROM categories c 
    LEFT JOIN vault_items v ON c.id = v.category_id 
    WHERE c.id = ?
    GROUP BY c.id
    """, (category_id,))
    updated = dict(cursor.fetchone())
    conn.close()
    return updated

@app.delete("/api/categories/{category_id}")
def delete_category(category_id: int, auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM categories WHERE id = ?", (category_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="ไม่พบหมวดหมู่นี้")
    
    # Check if this is the last category
    cursor.execute("SELECT COUNT(*) as count FROM categories")
    if cursor.fetchone()["count"] <= 1:
        conn.close()
        raise HTTPException(status_code=400, detail="ไม่สามารถลบหมวดหมู่สุดท้ายได้ ต้องมีอย่างน้อย 1 หมวดหมู่")

    # Delete category and its items (CASCADE)
    cursor.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    conn.close()
    return {"message": f"ลบหมวดหมู่ '{row['name']}' และรายการทั้งหมดในหมวดหมู่นี้เรียบร้อยแล้ว"}

# --- Vault Item CRUD ---

@app.get("/api/items")
def list_items(
    category_id: Optional[int] = None,
    q: Optional[str] = None,
    favorites_only: bool = False,
    auth: bool = Depends(check_auth)
):
    conn = get_db()
    cursor = conn.cursor()
    query = """
    SELECT v.*, c.name as category_name, c.icon as category_icon, c.color as category_color 
    FROM vault_items v
    JOIN categories c ON v.category_id = c.id
    WHERE 1=1
    """
    params = []

    if category_id:
        query += " AND v.category_id = ?"
        params.append(category_id)
    if favorites_only:
        query += " AND v.is_favorite = 1"
    if q:
        search_term = f"%{q.strip()}%"
        query += " AND (v.title LIKE ? OR v.username LIKE ? OR v.url LIKE ? OR v.notes LIKE ?)"
        params.extend([search_term, search_term, search_term, search_term])

    query += " ORDER BY v.is_favorite DESC, v.updated_at DESC, v.id DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()

    items = []
    for row in rows:
        item = dict(row)
        # Decrypt password for authenticated user
        item["password"] = decrypt_secret(item["password_encrypted"], conn)
        del item["password_encrypted"]
        items.append(item)

    conn.close()
    return items

@app.post("/api/items")
def create_item(item: VaultItemCreate, auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM categories WHERE id = ?", (item.category_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="หมวดหมู่ที่เลือกไม่ถูกต้อง")

    encrypted_pw = encrypt_secret(item.password, conn)
    now = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO vault_items (category_id, title, username, password_encrypted, url, notes, expires_at, is_favorite, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (item.category_id, item.title.strip(), item.username.strip(), encrypted_pw, item.url.strip(), item.notes.strip(), item.expires_at, item.is_favorite, now, now))
    conn.commit()
    new_id = cursor.lastrowid

    cursor.execute("""
    SELECT v.*, c.name as category_name, c.icon as category_icon, c.color as category_color 
    FROM vault_items v
    JOIN categories c ON v.category_id = c.id
    WHERE v.id = ?
    """, (new_id,))
    created = dict(cursor.fetchone())
    created["password"] = item.password
    del created["password_encrypted"]
    conn.close()
    return created

@app.put("/api/items/{item_id}")
def update_item(item_id: int, item: VaultItemUpdate, auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM vault_items WHERE id = ?", (item_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="ไม่พบรายการนี้")

    encrypted_pw = encrypt_secret(item.password, conn)
    now = datetime.now().isoformat()
    cursor.execute("""
    UPDATE vault_items 
    SET category_id = ?, title = ?, username = ?, password_encrypted = ?, url = ?, notes = ?, expires_at = ?, is_favorite = ?, updated_at = ?
    WHERE id = ?
    """, (item.category_id, item.title.strip(), item.username.strip(), encrypted_pw, item.url.strip(), item.notes.strip(), item.expires_at, item.is_favorite, now, item_id))
    conn.commit()

    cursor.execute("""
    SELECT v.*, c.name as category_name, c.icon as category_icon, c.color as category_color 
    FROM vault_items v
    JOIN categories c ON v.category_id = c.id
    WHERE v.id = ?
    """, (item_id,))
    updated = dict(cursor.fetchone())
    updated["password"] = item.password
    del updated["password_encrypted"]
    conn.close()
    return updated

@app.delete("/api/items/{item_id}")
def delete_item(item_id: int, auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    return {"message": "ลบรายการเรียบร้อยแล้ว"}

@app.post("/api/items/{item_id}/favorite")
def toggle_favorite(item_id: int, auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_favorite FROM vault_items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="ไม่พบรายการนี้")
    new_fav = 0 if row["is_favorite"] == 1 else 1
    cursor.execute("UPDATE vault_items SET is_favorite = ? WHERE id = ?", (new_fav, item_id))
    conn.commit()
    conn.close()
    return {"is_favorite": new_fav}

# --- Backup Export & Import ---

@app.get("/api/backup/export")
def export_backup(auth: bool = Depends(check_auth)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM categories ORDER BY sort_order ASC, id ASC")
    categories = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM vault_items ORDER BY id ASC")
    raw_items = [dict(r) for r in cursor.fetchall()]
    items = []
    for row in raw_items:
        row["password"] = decrypt_secret(row["password_encrypted"], conn)
        del row["password_encrypted"]
        items.append(row)
    conn.close()

    backup_data = {
        "version": "1.0",
        "exported_at": datetime.now().isoformat(),
        "categories": categories,
        "items": items
    }
    return JSONResponse(
        content=backup_data,
        headers={"Content-Disposition": f"attachment; filename=thaid_vault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"}
    )

@app.post("/api/backup/import")
def import_backup(data: Dict[str, Any], auth: bool = Depends(check_auth)):
    if "categories" not in data or "items" not in data:
        raise HTTPException(status_code=400, detail="รูปแบบไฟล์สำรองข้อมูลไม่ถูกต้อง")
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Import categories mapping old ID to new ID
        category_map = {}
        for cat in data["categories"]:
            cursor.execute("SELECT id FROM categories WHERE slug = ? OR name = ?", (cat.get("slug", ""), cat["name"]))
            existing = cursor.fetchone()
            if existing:
                category_map[cat["id"]] = existing["id"]
            else:
                slug = cat.get("slug") or f"cat_{secrets.token_hex(4)}"
                cursor.execute("""
                INSERT INTO categories (slug, name, icon, color, description, sort_order)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (slug, cat["name"], cat.get("icon", "folder"), cat.get("color", "#0071e3"), cat.get("description", ""), cat.get("sort_order", 0)))
                category_map[cat["id"]] = cursor.lastrowid

        # Import items
        imported_count = 0
        now = datetime.now().isoformat()
        for item in data["items"]:
            cat_id = category_map.get(item["category_id"])
            if not cat_id:
                # Fallback to first available category
                cursor.execute("SELECT id FROM categories LIMIT 1")
                cat_id = cursor.fetchone()["id"]
            pw_enc = encrypt_secret(item.get("password", ""), conn)
            cursor.execute("""
            INSERT INTO vault_items (category_id, title, username, password_encrypted, url, notes, expires_at, is_favorite, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (cat_id, item["title"], item.get("username", ""), pw_enc, item.get("url", ""), item.get("notes", ""), item.get("expires_at", ""), item.get("is_favorite", 0), now, now))
            imported_count += 1

        conn.commit()
        conn.close()
        return {"message": f"นำเข้าข้อมูลสำเร็จ: {imported_count} รายการ"}
    except Exception as e:
        conn.rollback()
        conn.close()
        raise HTTPException(status_code=500, detail=f"เกิดข้อผิดพลาดในการนำเข้าข้อมูล: {str(e)}")

# --- Serve Frontend ---
STATIC_DIR = os.path.join(BASE_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", response_class=HTMLResponse)
def index():
    html_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(html_file):
        with open(html_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h3>ThaiD Vault Loading...</h3>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8088, reload=True)

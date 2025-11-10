from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, IPvAnyAddress
from typing import Optional, List
from datetime import datetime
import sqlite3
import os
from loguru import logger
from fastapi.middleware.cors import CORSMiddleware
from threading import Thread
from api.auto_learning import monitor_logs

# Import firewall utils
from api.firewall.iptables_utils import (
    add_rule_to_iptables,
    delete_rule_from_iptables,
)

# Import sniffer
from api.ai_detector.sniffer import start_sniffer


# --- Initialisation FastAPI ---
app = FastAPI(
    title="Firewall Intelligent Programmable",
    description="API REST pour gérer iptables + AI Detector",
    version="1.0.0",
)

origins = ["http://localhost:5173", "http://127.0.0.1:5173", "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Logger ---
os.makedirs("logs", exist_ok=True)
logger.add("logs/firewall_api.log", rotation="1 MB", retention="10 days", level="INFO")

# --- Base SQLite ---
DB_PATH = "db/firewall.db"
os.makedirs("db", exist_ok=True)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            action TEXT NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


init_db()


# --- Pydantic Models ---
class RuleIn(BaseModel):
    ip: Optional[IPvAnyAddress] = None
    port: Optional[int] = None
    action: str
    protocol: Optional[str] = "tcp"


class RuleOut(BaseModel):
    id: int
    ip: Optional[IPvAnyAddress] = None
    port: Optional[int] = None
    action: str
    protocol: Optional[str] = "tcp"
    created_at: str


# --- DB Operations ---
def save_rule(rule: RuleIn):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO rules (ip, port, action, protocol, created_at) VALUES (?, ?, ?, ?, ?)",
        (str(rule.ip) if rule.ip else None,
         rule.port,
         rule.action.upper(),
         rule.protocol,
         datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def fetch_rules() -> List[RuleOut]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, ip, port, action, protocol, created_at FROM rules ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    results = []
    for r in rows:
        ip_val = r[1] if r[1] not in (None, 'None', '') else None
        results.append(RuleOut(
            id=r[0],
            ip=ip_val,
            port=r[2],
            action=r[3],
            protocol=r[4],
            created_at=r[5]
        ))
    return results


def delete_rule_from_db(rule_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()


# --- Sniffer auto start ---
@app.on_event("startup")
def start_learning():
    t = Thread(target=monitor_logs, daemon=True)
    t.start()


# --- API Endpoints ---
@app.get("/")
def home():
    return {"message": "✅ Firewall Intelligent API opérationnelle."}


@app.get("/rules", response_model=List[RuleOut])
def get_rules():
    return fetch_rules()


@app.post("/rules")
def add_rule(rule: RuleIn):
    success = add_rule_to_iptables(rule)
    if not success:
        raise HTTPException(500, "Échec ajout iptables")

    save_rule(rule)
    logger.info(f"Règle ajoutée : {rule.action} {rule.ip}:{rule.port}")

    return {"status": "success", "rule": rule}


@app.delete("/rules/{rule_id}")
def remove_rule(rule_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip, port, protocol FROM rules WHERE id=?", (rule_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(404, "Règle introuvable")

    ip, port, protocol = row

    success = delete_rule_from_iptables(ip=ip, port=port, protocol=protocol)
    delete_rule_from_db(rule_id)

    if not success:
        return {"status": "db_only", "rule_id": rule_id}

    return {"status": "deleted", "rule_id": rule_id}


# --- run local ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

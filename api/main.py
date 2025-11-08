from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, IPvAnyAddress
from typing import Optional, List
from datetime import datetime
import subprocess
import sqlite3
import os
from loguru import logger
from fastapi.middleware.cors import CORSMiddleware

# === Initialisation FastAPI ===
app = FastAPI(
    title="Firewall Intelligent Programmable",
    description="API REST pour gérer dynamiquement les règles iptables et journaliser les actions.",
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

# === Logger ===
os.makedirs("logs", exist_ok=True)
logger.add("logs/firewall_api.log", rotation="1 MB", retention="10 days", level="INFO")

# === Base SQLite ===
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

# === Schémas Pydantic ===
class RuleIn(BaseModel):
    ip: Optional[IPvAnyAddress] = None
    port: Optional[int] = None
    action: str  # "ALLOW" ou "BLOCK"
    protocol: Optional[str] = "tcp"

class RuleOut(BaseModel):
    id: int
    ip: Optional[IPvAnyAddress] = None
    port: Optional[int] = None
    action: str
    protocol: Optional[str] = "tcp"
    created_at: str

# === Utilitaires système ===
def run_cmd(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur commande iptables : {' '.join(cmd)} -> {e}")
        return False

# === Gestion des règles iptables ===
def add_rule_to_iptables(rule: RuleIn) -> bool:
    cmd = ["sudo", "iptables", "-A", "INPUT"]
    if rule.ip:
        cmd += ["-s", str(rule.ip)]
    if rule.port:
        cmd += ["-p", rule.protocol or "tcp", "--dport", str(rule.port)]
    target = "DROP" if rule.action.upper() == "BLOCK" else "ACCEPT"
    cmd += ["-j", target]
    return run_cmd(cmd)

def delete_rule_from_iptables(ip: Optional[str], port: Optional[int], protocol: str = "tcp") -> bool:
    """
    Supprime une règle iptables en recherchant son numéro de ligne exact.
    Fonctionne même si la règle existe en DROP uniquement, en ACCEPT uniquement,
    ou avec aucun IP (port global).
    """

    # 1. Lister les règles
    result = subprocess.run(["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
                            capture_output=True, text=True)

    lines = result.stdout.split("\n")

    rule_number = None

    for line in lines:
        if not line.strip():
            continue

        # exemple ligne :
        # "3    DROP    tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:80"
        parts = line.split()

        if parts[0].isdigit():
            num = parts[0]

            # Chercher port et/ou IP dans la ligne
            if ip and ip not in line:
                continue

            if port and f"dpt:{port}" not in line:
                continue

            # OK, règle trouvée
            rule_number = num
            break

    if not rule_number:
        logger.warning(f"Aucune règle correspondante dans iptables: ip={ip}, port={port}")
        return False

    # 2. Suppression par numéro de ligne
    del_cmd = ["sudo", "iptables", "-D", "INPUT", rule_number]

    try:
        subprocess.run(del_cmd, check=True)
        logger.info(f"Règle iptables supprimée (ligne {rule_number}) : ip={ip}, port={port}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur suppression iptables: {e}")
        return False


# === Gestion DB ===
def save_rule(rule: RuleIn):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO rules (ip, port, action, protocol, created_at) VALUES (?, ?, ?, ?, ?)",
        (str(rule.ip) if rule.ip else None, rule.port, rule.action.upper(), rule.protocol, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def fetch_rules() -> List[RuleOut]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, ip, port, action, protocol, created_at FROM rules ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    result = []
    for r in rows:
        ip_val = r[1] if r[1] not in (None, 'None', '') else None
        result.append(RuleOut(
            id=r[0],
            ip=ip_val,
            port=r[2],
            action=r[3],
            protocol=r[4],
            created_at=r[5]
        ))
    return result

def delete_rule(rule_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()

# === Endpoints ===
@app.get("/", tags=["Status"])
def home():
    return {"message": "✅ Firewall Intelligent API opérationnelle."}

@app.get("/rules", response_model=List[RuleOut], tags=["Rules"])
def get_rules():
    return fetch_rules()

@app.post("/rules", response_model=dict, tags=["Rules"])
def add_rule(rule: RuleIn):
    success = add_rule_to_iptables(rule)
    if not success:
        raise HTTPException(status_code=500, detail="Échec ajout règle iptables")
    save_rule(rule)
    logger.info(f"Règle ajoutée : {rule.action} {rule.ip}:{rule.port}")
    return {"status": "success", "rule": rule}

@app.delete("/rules/{rule_id}", tags=["Rules"])
def remove_rule(rule_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT ip, port, protocol FROM rules WHERE id=?", (rule_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Règle non trouvée")
    ip, port, protocol = row
    success = delete_rule_from_iptables(ip=ip, port=port, protocol=protocol)
    delete_rule(rule_id)
    if not success:
        logger.warning(f"Aucune règle iptables correspondante pour {ip}:{port}")
        return {"status": "deleted_from_db_only", "rule_id": rule_id, "message": "Supprimée de DB, mais pas dans iptables"}
    logger.info(f"Règle supprimée : {ip}:{port} (id={rule_id})")
    return {"status": "deleted", "rule_id": rule_id}

# === Run ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

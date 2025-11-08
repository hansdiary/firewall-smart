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

<<<<<<< Updated upstream
origins = ["http://localhost:5173", "http://127.0.0.1:5173", "*"]
=======
# === CORS pour React ===
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "*"  # à enlever en prod
]
>>>>>>> Stashed changes
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

<<<<<<< Updated upstream
# === Logger ===
os.makedirs("logs", exist_ok=True)
logger.add("logs/firewall_api.log", rotation="1 MB", retention="10 days", level="INFO")

# === Base SQLite ===
=======
# === Logging ===
os.makedirs("logs", exist_ok=True)
logger.add("logs/firewall_api.log", rotation="1 MB", retention="10 days", level="INFO")

# === DB ===
>>>>>>> Stashed changes
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
            action TEXT,
            protocol TEXT DEFAULT 'tcp',
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# === Pydantic schemas ===
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

<<<<<<< Updated upstream
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

def delete_rule_from_iptables(port: Optional[int] = None, ip: Optional[str] = None, protocol: str = "tcp", action: str = "BLOCK") -> bool:
    """Supprime une règle iptables spécifique."""
    target = "DROP" if action.upper() == "BLOCK" else "ACCEPT"
    base_cmd = ["sudo", "iptables", "-D", "INPUT"]
    
    if ip:
        base_cmd += ["-s", ip]
    base_cmd += ["-p", protocol]
    if port:
        base_cmd += ["--dport", str(port)]
    
    cmd = base_cmd + ["-j", target]
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        logger.error(f"Erreur suppression iptables : {' '.join(cmd)}")
        return False


# === Gestion DB ===
=======
# === Utilitaires iptables ===
def build_iptables_args(rule: RuleIn):
    args = []
    if rule.protocol:
        args += ["-p", rule.protocol]
    if rule.port:
        args += ["--dport", str(rule.port)]
    if rule.ip:
        args += ["-s", str(rule.ip)]
    action = "ACCEPT" if rule.action.upper() == "ALLOW" else "DROP"
    args += ["-j", action]
    return args

def run_iptables(cmd_type: str, rule: RuleIn) -> bool:
    """Ajoute ou supprime une règle iptables."""
    cmd = ["sudo", "iptables", f"-{cmd_type}", "INPUT"] + build_iptables_args(rule)
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0

# === DB functions ===
>>>>>>> Stashed changes
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

def delete_rule_db(rule_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()

<<<<<<< Updated upstream
=======
def get_rule_by_id(rule_id: int) -> Optional[RuleOut]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, ip, port, action, protocol, created_at FROM rules WHERE id=?", (rule_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return RuleOut(id=row[0], ip=row[1], port=row[2], action=row[3], protocol=row[4], created_at=row[5])
    return None

>>>>>>> Stashed changes
# === Endpoints ===
@app.get("/", tags=["Status"])
def home():
    return {"message": "✅ Firewall Intelligent API opérationnelle."}

@app.get("/rules", response_model=List[RuleOut], tags=["Rules"])
def get_rules():
    return fetch_rules()

<<<<<<< Updated upstream
@app.post("/rules", response_model=dict, tags=["Rules"])
def add_rule(rule: RuleIn):
    success = add_rule_to_iptables(rule)
    if not success:
        raise HTTPException(status_code=500, detail="Échec ajout règle iptables")
=======
@app.post("/rules", response_model=RuleOut, tags=["Rules"])
def add_rule(rule: RuleIn):
    if not rule.ip and not rule.port:
        raise HTTPException(status_code=422, detail="IP ou port doit être renseigné")
    success = run_iptables("A", rule)
    if not success:
        raise HTTPException(status_code=500, detail="Échec ajout iptables")
>>>>>>> Stashed changes
    save_rule(rule)
    saved_rule = fetch_rules()[0]
    logger.info(f"Règle ajoutée : {rule.action} {rule.ip}:{rule.port}")
    return saved_rule
9

@app.delete("/rules/{rule_id}", tags=["Rules"])
def remove_rule(rule_id: int):
<<<<<<< Updated upstream
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
=======
    rule = get_rule_by_id(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Règle non trouvée")

    success = run_iptables("D", rule)

    # Supprimer de la DB quoi qu'il arrive
    delete_rule_db(rule_id)

    if success:
        logger.info(f"Règle supprimée d'iptables et DB : {rule}")
        return {"status": "deleted", "rule_id": rule_id}
    else:
        logger.warning(f"Aucune règle iptables correspondante trouvée pour {rule.ip}")
        return {
            "status": "deleted_from_db_only",
            "rule_id": rule_id,
            "message": "La règle n'existait pas dans iptables, mais a été supprimée de la base."
        }
>>>>>>> Stashed changes

# === Run ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

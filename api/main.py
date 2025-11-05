from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, IPvAnyAddress
from typing import Optional, List
from datetime import datetime
import subprocess
import sqlite3
import os
from loguru import logger

# === Initialisation ===
app = FastAPI(
    title="Firewall Intelligent Programmable",
    description="API REST pour gérer dynamiquement les règles iptables et journaliser les actions.",
    version="1.0.0",
)

# === Configuration du journal ===
os.makedirs("logs", exist_ok=True)
logger.add("logs/firewall_api.log", rotation="1 MB", retention="10 days", level="INFO")

# === Base de données SQLite ===
DB_PATH = "db/firewall.db"
os.makedirs("db", exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
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
    ip: IPvAnyAddress
    port: Optional[int] = None
    action: str  # "ALLOW" or "BLOCK"
    protocol: Optional[str] = "tcp"

class RuleOut(RuleIn):
    id: int
    created_at: str

# === Utilitaires système ===
def run_cmd(cmd: str) -> bool:
    """Exécute une commande système en sécurité."""
    try:
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur commande : {e}")
        return False

# === Fonctions de gestion de règles ===
def add_rule_to_iptables(rule: RuleIn) -> bool:
    """Ajoute une règle iptables selon l'action."""
    if rule.action.upper() == "BLOCK":
        cmd = f"sudo iptables -A INPUT -s {rule.ip} -p {rule.protocol}"
        if rule.port:
            cmd += f" --dport {rule.port}"
        cmd += " -j DROP"
    elif rule.action.upper() == "ALLOW":
        cmd = f"sudo iptables -A INPUT -s {rule.ip} -p {rule.protocol}"
        if rule.port:
            cmd += f" --dport {rule.port}"
        cmd += " -j ACCEPT"
    else:
        return False
    return run_cmd(cmd)

def delete_rule_from_iptables(rule_id: int, ip: str) -> bool:
    """Supprime une règle basée sur son IP."""
    cmd = f"sudo iptables -D INPUT -s {ip} -j DROP || sudo iptables -D INPUT -s {ip} -j ACCEPT"
    return run_cmd(cmd)

# === Fonctions DB ===
def save_rule(rule: RuleIn):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO rules (ip, port, action, protocol, created_at) VALUES (?, ?, ?, ?, ?)",
              (str(rule.ip), rule.port, rule.action.upper(), rule.protocol, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def fetch_rules() -> List[RuleOut]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, ip, port, action, protocol, created_at FROM rules ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [RuleOut(id=r[0], ip=r[1], port=r[2], action=r[3], protocol=r[4], created_at=r[5]) for r in rows]

def delete_rule(rule_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()

# === Endpoints REST ===

@app.get("/", tags=["Status"])
def home():
    return {"message": "✅ Firewall Intelligent API opérationnelle."}

@app.get("/rules", response_model=List[RuleOut], tags=["Rules"])
def get_rules():
    """Lister toutes les règles enregistrées."""
    return fetch_rules()

@app.post("/rules", tags=["Rules"], response_model=dict)
def add_rule(rule: RuleIn):
    """Ajouter une nouvelle règle (BLOCK ou ALLOW)."""
    success = add_rule_to_iptables(rule)
    if not success:
        raise HTTPException(status_code=500, detail="Échec lors de l’ajout de la règle iptables.")
    save_rule(rule)
    logger.info(f"Règle ajoutée : {rule.action} {rule.ip}:{rule.port}")
    return {"status": "success", "rule": rule}

@app.delete("/rules/{rule_id}", tags=["Rules"])
def remove_rule(rule_id: int, ip: str = Query(..., description="Adresse IP à supprimer")):
    """Supprimer une règle spécifique."""
    success = delete_rule_from_iptables(rule_id, ip)
    if not success:
        raise HTTPException(status_code=500, detail="Impossible de supprimer la règle iptables.")
    delete_rule(rule_id)
    logger.info(f"Règle supprimée : {ip} (id={rule_id})")
    return {"status": "deleted", "rule_id": rule_id}

# === Run local ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)

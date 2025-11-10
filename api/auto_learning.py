import time
import re
import subprocess
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
from loguru import logger

DB_PATH = "db/firewall.db"
LOG_FILE = "/var/log/auth.log"   # fichier à surveiller
SCORE_THRESHOLD = 20             # seuil de blocage

scores = defaultdict(int)
last_event = defaultdict(list)

# Regex pour tentatives SSH échouées
SSH_FAILED_REGEX = re.compile(
    r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
)

# Regex pour accès root interdit
SSH_ROOT_REGEX = re.compile(
    r"Failed password for root from (\d+\.\d+\.\d+\.\d+)"
)


def block_ip(ip):
    """Ajoute la règle iptables + enregistre dans DB"""
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        logger.info(f"[AUTO] IP automatiquement bloquée : {ip}")
    except Exception as e:
        logger.error(f"Erreur iptables: {e}")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO rules (ip, port, action, protocol, created_at) VALUES (?, ?, ?, ?, ?)",
        (ip, None, "BLOCK", "tcp", datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def analyze_line(line):
    """Analyse une ligne de log et met à jour le score IP"""

    # 1. Tentative SSH échouée
    failed = SSH_FAILED_REGEX.search(line)
    if failed:
        ip = failed.group(1)
        scores[ip] += 1
        return

    # 2. Tentative root interdite
    root = SSH_ROOT_REGEX.search(line)
    if root:
        ip = root.group(1)
        scores[ip] += 5
        return


def monitor_logs():
    """Surveille en continu le fichier de logs"""
    logger.info("🧠 Démarrage du module d'auto-apprentissage…")

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # aller à la fin du fichier

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            analyze_line(line)

            # Vérifier si des IP dépassent le seuil
            for ip, score in list(scores.items()):
                if score >= SCORE_THRESHOLD:
                    block_ip(ip)
                    scores[ip] = 0  # reset après blocage

import subprocess
from typing import Optional, List
from loguru import logger

# --- Exécution commande système ---
def run_cmd(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur iptables : {' '.join(cmd)} -> {e}")
        return False


# --- AJOUT règle iptables ---
def add_rule_to_iptables(rule):
    cmd = ["sudo", "iptables", "-A", "INPUT"]

    if rule.ip:
        cmd += ["-s", str(rule.ip)]

    if rule.port:
        cmd += ["-p", rule.protocol or "tcp", "--dport", str(rule.port)]

    target = "DROP" if rule.action.upper() == "BLOCK" else "ACCEPT"
    cmd += ["-j", target]

    return run_cmd(cmd)


# --- SUPPRESSION règle iptables ---
def delete_rule_from_iptables(ip: Optional[str], port: Optional[int], protocol: str = "tcp") -> bool:
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
        capture_output=True,
        text=True
    )

    lines = result.stdout.split("\n")
    rule_number = None

    for line in lines:
        if not line.strip():
            continue

        parts = line.split()
        if not parts[0].isdigit():
            continue

        if ip and ip not in line:
            continue

        if port and f"dpt:{port}" not in line:
            continue

        rule_number = parts[0]
        break

    if not rule_number:
        logger.warning(f"Aucune règle iptables trouvée: ip={ip}, port={port}")
        return False

    del_cmd = ["sudo", "iptables", "-D", "INPUT", rule_number]

    try:
        subprocess.run(del_cmd, check=True)
        logger.info(f"Règle supprimée de iptables: ligne={rule_number}, ip={ip}, port={port}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur suppression iptables: {e}")
        return False

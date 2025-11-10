# sniffer.py
import joblib
import os
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from api.main import add_rule_to_iptables  # pour bloquer les IP
from loguru import logger

# === Charger le modèle ML ===
MODEL_PATH = "api/ai_detector/model.pkl"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Le fichier modèle est manquant : {MODEL_PATH}")

model = joblib.load(MODEL_PATH)
logger.info("🧠 IDS/IPS ML chargé avec succès")

# === Fonction utilitaire pour convertir IP en entier ===
def ip_to_int(ip_str):
    parts = list(map(int, ip_str.split(".")))
    return (parts[0]<<24) + (parts[1]<<16) + (parts[2]<<8) + parts[3]

# === Fonction de prédiction sur un paquet ===
def is_malicious(pkt):
    if IP in pkt:
        ip_num = ip_to_int(pkt[IP].src)
        proto = pkt[IP].proto
        length = len(pkt)
        port = None
        if TCP in pkt:
            port = pkt[TCP].dport
            proto = 6
        elif UDP in pkt:
            port = pkt[UDP].dport
            proto = 17
        # Créer dataframe avec les mêmes colonnes que le training
        df = pd.DataFrame([{
            "ip_num": ip_num,
            "port": port,
            "proto": proto,
            "length": length
        }])
        pred = model.predict(df)[0]
        return bool(pred), pkt[IP].src
    return False, None

# === Callback pour chaque paquet sniffé ===
def process_packet(pkt):
    malicious, ip = is_malicious(pkt)
    if malicious:
        logger.warning(f"❌ IP suspecte détectée : {ip}")
        # Bloquer l'IP via iptables
        from api.main import RuleIn
        rule = RuleIn(ip=ip, action="BLOCK")
        add_rule_to_iptables(rule)

# === Fonction pour démarrer le sniffer ===
def start_sniffer():
    logger.info("🧠 IDS/IPS ML démarré…")
    sniff(prn=process_packet, store=False, filter="ip")

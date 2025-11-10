def extract_features(pkt):
    """
    Transforme un paquet en vecteur numérique : DATA -> FEATURES
    """
    try:
        ip = pkt[1].src if hasattr(pkt[1], "src") else None
        length = len(pkt)
        flags = pkt.sprintf("%TCP.flags%") if pkt.haslayer("TCP") else "NONE"
        is_syn = 1 if "S" in flags else 0
        is_fin = 1 if "F" in flags else 0
        is_rst = 1 if "R" in flags else 0

        return [
            ip,
            length,
            is_syn,
            is_fin,
            is_rst
        ]
    except:
        return None

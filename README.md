# Firewall intelligent programmable — README

## Contexte & objectif
Ce projet a pour but de fournir un **PoC** (preuve de concept) d’un « firewall intelligent programmable » :
- manipuler les règles `iptables` depuis Python de façon sécurisée,  
- fournir une interface (CLI pour le PoC, API REST prévue),  
- poser les bases pour un module d’auto-apprentissage détectant et bloquant automatiquement des IP suspectes à partir de logs.

C’est un prototype pour usage en environnement de développement/VM isolée — ne pas déployer tel quel sur un serveur de production sans revue.

---

## Fonctionnalités
- **Module `IptablesCtl` (PoC)** :
  - ajouter une règle DROP ciblant une IP (IPv4/IPv6 validée),
  - lister les règles (avec `--line-numbers`),
  - rechercher et supprimer des règles contenant une IP donnée.
- **CLI simple `tools/manage_rule.py`** :
  - `block`, `unblock`, `list`.
- **Tests unitaires** qui moquent `subprocess.run` pour éviter toute modification réelle d’iptables lors des tests.


## Architecture du projet

firewall-smart/
├── api/ # (à venir) FastAPI app
├── firewall/
│ └── iptables_ctl.py # PoC : interface iptables
├── tools/
│ └── manage_rule.py # CLI PoC
├── autoscan/ # (à venir) watcher + detector
├── storage/ # (à venir) sqlite / ORM
├── tests/
│ └── test_iptables_ctl.py
├── requirements.txt
└── README.md


---

## Prérequis
- Linux (iptables) — testé sur distributions classiques.  
- Python 3.9+ (3.10 recommandé).  
- Pour exécuter les commandes réelles : privilèges root (ou capability `CAP_NET_ADMIN` dans un conteneur).  
- `iptables` installé (`/sbin/iptables` ou `/usr/sbin/iptables` selon la distro).

---



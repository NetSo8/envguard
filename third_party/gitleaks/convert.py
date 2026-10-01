#!/usr/bin/env python3
"""Convertit gitleaks.toml (règles officielles de gitleaks, MIT) en rules.json
pour envguard, sans dépendance TOML côté Go.

Mise à jour des règles :
  curl -sfLo gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
  python3 convert.py
"""
import json, tomllib

d = tomllib.load(open("gitleaks.toml", "rb"))
rules = []
for r in d["rules"]:
    # Règles liées à un chemin de fichier : sans objet pour un corps de requête.
    if "regex" not in r or "path" in r:
        continue
    out = {"id": r["id"], "regex": r["regex"], "keywords": [k.lower() for k in r.get("keywords", [])]}
    if "entropy" in r:
        out["entropy"] = r["entropy"]
    if "secretGroup" in r:
        out["secretGroup"] = r["secretGroup"]
    al = []
    for a in r.get("allowlists", []) + ([r["allowlist"]] if "allowlist" in r else []):
        if "paths" in a and not ("regexes" in a or "stopwords" in a):
            continue
        al.append({k: a[k] for k in ("regexes", "regexTarget", "stopwords", "condition") if k in a})
    if al:
        out["allowlists"] = al
    rules.append(out)
g = d.get("allowlist", {})
json.dump({"rules": rules, "allowlist": {"regexes": g.get("regexes", []), "stopwords": g.get("stopwords", [])}},
          open("rules.json", "w"), ensure_ascii=False, separators=(",", ":"))
print(len(rules), "règles")

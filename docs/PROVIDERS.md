# Commandes par fournisseur

Ce guide montre comment brancher chaque fournisseur sur envguard. Le plus simple reste `envguard run -- <outil>` (voir le [README](../README.md)), qui règle ces variables tout seul. Les commandes ci-dessous servent quand le proxy tourne seul (`./envguard`, port 8787) ou pour un outil qui ne lit pas les variables habituelles.

## Principe du routage

Chaque fournisseur a sa route : `http://127.0.0.1:8787/<nom>` remplace la base URL officielle, le reste du chemin est inchangé.

```
http://127.0.0.1:8787/groq/v1/chat/completions  →  https://api.groq.com/openai/v1/chat/completions
```

Ta clé du fournisseur (header `Authorization`, `x-api-key`, `x-goog-api-key`) est transmise telle quelle : seul le **contenu** des requêtes est masqué.

Dans les exemples ci-dessous, remplace `$MODEL` par le modèle voulu.

---

### Anthropic (Claude)

Claude Code :

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic claude
```

SDK (Python / TypeScript) : `base_url="http://127.0.0.1:8787/anthropic"`.

```bash
curl http://127.0.0.1:8787/anthropic/v1/messages -H "x-api-key: $ANTHROPIC_API_KEY" -H "anthropic-version: 2023-06-01" -H "content-type: application/json" -d '{"model":"'$MODEL'","max_tokens":256,"messages":[{"role":"user","content":"ma clé: sk-ant-api03-exemple0123456789abcdefghij"}]}'
```

### OpenAI

Codex et SDK OpenAI :

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1 codex
```

```bash
curl http://127.0.0.1:8787/openai/v1/chat/completions -H "Authorization: Bearer $OPENAI_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","stream":true,"messages":[{"role":"user","content":"hello"}]}'
```

L'API Responses passe par la même route : `/openai/v1/responses`.

### Google Gemini

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

### DeepSeek

Format OpenAI :

```bash
curl http://127.0.0.1:8787/deepseek/chat/completions -H "Authorization: Bearer $DEEPSEEK_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

Format Anthropic (Claude Code avec les modèles DeepSeek) :

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8787/deepseek/anthropic ANTHROPIC_AUTH_TOKEN=$DEEPSEEK_API_KEY claude
```

### Meta (Muse Spark)

Chat Completions, Responses et Messages sont tous disponibles.

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/meta/v1 OPENAI_API_KEY=$MODEL_API_KEY codex
```

```bash
curl http://127.0.0.1:8787/meta/v1/chat/completions -H "Authorization: Bearer $MODEL_API_KEY" -H "content-type: application/json" -d '{"model":"muse-spark-1.1","messages":[{"role":"user","content":"hello"}]}'
```

### xAI (Grok)

```bash
curl http://127.0.0.1:8787/xai/v1/chat/completions -H "Authorization: Bearer $XAI_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Mistral

```bash
curl http://127.0.0.1:8787/mistral/v1/chat/completions -H "Authorization: Bearer $MISTRAL_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Groq

```bash
curl http://127.0.0.1:8787/groq/v1/chat/completions -H "Authorization: Bearer $GROQ_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### OpenRouter

```bash
OPENAI_BASE_URL=http://127.0.0.1:8787/openrouter/v1 OPENAI_API_KEY=$OPENROUTER_API_KEY codex
```

```bash
curl http://127.0.0.1:8787/openrouter/v1/chat/completions -H "Authorization: Bearer $OPENROUTER_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Together AI

```bash
curl http://127.0.0.1:8787/together/v1/chat/completions -H "Authorization: Bearer $TOGETHER_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Fireworks AI

```bash
curl http://127.0.0.1:8787/fireworks/v1/chat/completions -H "Authorization: Bearer $FIREWORKS_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Qwen (Alibaba DashScope, international)

```bash
curl http://127.0.0.1:8787/qwen/v1/chat/completions -H "Authorization: Bearer $DASHSCOPE_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

Région Chine : `-provider qwen=https://dashscope.aliyuncs.com/compatible-mode`.

### Moonshot (Kimi)

```bash
curl http://127.0.0.1:8787/moonshot/v1/chat/completions -H "Authorization: Bearer $MOONSHOT_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Z.ai (GLM)

La base officielle contient déjà la version, la route n'a donc pas de `/v1` :

```bash
curl http://127.0.0.1:8787/zai/chat/completions -H "Authorization: Bearer $ZAI_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Perplexity

```bash
curl http://127.0.0.1:8787/perplexity/chat/completions -H "Authorization: Bearer $PERPLEXITY_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Cohere (compatibilité OpenAI)

```bash
curl http://127.0.0.1:8787/cohere/v1/chat/completions -H "Authorization: Bearer $COHERE_API_KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

### Ollama (local)

```bash
curl http://127.0.0.1:8787/ollama/v1/chat/completions -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

L'API native `/api/chat` d'Ollama n'est pas gérée en streaming : utilise `/v1`.

### Autre fournisseur compatible OpenAI

```bash
./envguard -provider monfournisseur=https://api.exemple.com
```

```bash
curl http://127.0.0.1:8787/monfournisseur/v1/chat/completions -H "Authorization: Bearer $KEY" -H "content-type: application/json" -d '{"model":"'$MODEL'","messages":[{"role":"user","content":"hello"}]}'
```

`-provider` surcharge aussi un fournisseur existant (URL régionale, passerelle d'entreprise…).

---


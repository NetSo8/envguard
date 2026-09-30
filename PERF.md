# Rapport de performance — envguard

Mesures prises le 30/09/2026 sur Apple M1 (8 cœurs), Go 1.27.1, macOS. Données synthétiques mais réalistes : conversations d'agent de code (extraits Go, sorties `git log`, JSON, texte FR, ~24 secrets distincts) et flux SSE d'environ 2 000 deltas de 4 à 12 caractères.

Reproduire :

```bash
go test -run '^$' -bench 'Mask/|Rehydrate|SSE|Hint' .
```

```bash
PERF=1 CONC=1 go test -run TestLoad -v .
```

## En bref

| Question | Réponse |
|---|---|
| Mémoire au repos | **~11 Mo RSS**, binaire de 11,7 Mo |
| Mémoire en usage normal (1 client) | **18 à 26 Mo** (runtime Go, tas de 3 à 6 Mo) |
| Mémoire sous forte charge (32 requêtes parallèles, bodies de 512 Ko) | ~120 Mo (contre ~200 Mo avant) |
| Latence ajoutée, requête de 64 Ko | **0,67 ms** sans secret, **0,76 ms** avec secrets |
| Latence ajoutée, requête de 512 Ko avec secrets | **5,5 ms** (contre 12,2 ms avant) |
| Coût du streaming, sans secret connu | **~45 à 75 ns par event** |
| Coût du streaming, secret connu | **1,2 à 5,3 µs par event**, soit ~8 ms sur une réponse entière |

Un appel LLM prend entre 1 et 60 secondes : le surcoût d'envguard est **imperceptible** (moins de 0,5 %).

## Optimisations appliquées

1. **Remplacement multi-motifs en une seule passe** ([replace.go](replace.go)). Un index par premier octet (`[256][]uint16`, construit une fois à chaque nouveau secret) ne teste, à chaque position, que les motifs qui commencent par cet octet, du plus long au plus court. Rien n'est copié tant qu'aucun motif n'est trouvé ; ensuite, **une seule allocation**, quel que soit le nombre de secrets. Avant : une copie complète du body par secret présent.
2. **Consigne insérée sans décoder le JSON** ([hint.go](hint.go)). Un mini-scanner localise `system`, `instructions`, `messages` ou `systemInstruction` au premier niveau, puis le texte est inséré directement dans les octets. Toutes les formes sont gérées : champ absent, `null`, string, tableau vide ou non, objet Gemini sans `parts`. Bonus : l'ordre des clés et le formatage d'origine sont conservés. L'ancienne méthode passait par une `map` et triait les clés.
3. **Bonus : secrets déjà connus sans allocation.** Les secrets déjà enregistrés sont vérifiés via `m[string(bytes)]`, que le compilateur Go optimise sans allouer. Avant, chaque secret connu coûtait une conversion `string` par requête.

## Avant / après — micro-benchmarks

### Masquage avec ~24 secrets (`Vault.Mask`)

| Body | Temps avant → après | Mémoire avant → après | Allocs avant → après |
|---|---|---|---|
| 4 Ko | 29 → 31 µs | 14 Ko → **4,8 Ko** | 6 → **1** |
| 64 Ko | 1,16 → **0,56 ms** | 1,5 Mo → **77 Ko** (÷20) | 75 → **2** |
| 512 Ko | 8,9 → **4,5 ms** | 12,6 Mo → **616 Ko** (÷20) | 431 → **5** |
| 2 Mo | 34 → **18 ms** | 50 Mo → **2,5 Mo** (÷20) | 1 641 → **8** |

Sans secret, rien ne change : **0 allocation**, ~187 Mo/s.

### Réhydratation (`Vault.Rehydrate`)

| Body | Débit avant → après | Mémoire avant → après | Allocs avant → après |
|---|---|---|---|
| 64 Ko | 217 → **490 Mo/s** | 1,6 Mo → **74 Ko** | 24 → **1** |
| 512 Ko | 201 → **491 Mo/s** | 12,6 Mo → **557 Ko** | 25 → **1** |
| 2 Mo | 242 → **455 Mo/s** | 50 Mo → **2,2 Mo** | 24 → **1** |

### Consigne dans le system prompt, body de 64 Ko

| | Avant (décodage JSON complet) | Après (insertion directe) |
|---|---|---|
| Temps | ~0,4 ms (estimé) | **50 µs** (1,3 Go/s) |
| Mémoire | ~380 Ko | **72 Ko** (le body de sortie) |
| Allocs | des centaines | **1** |

### Streaming SSE (inchangé, pas ciblé par ces optimisations)

| Format | Aucun secret connu | Secret connu |
|---|---|---|
| Anthropic | 71 ns/event | 1,2 µs/event · ~6 allocs/event |
| OpenAI Chat | 49 ns/event | 5,3 µs/event · ~43 allocs/event |
| OpenAI Responses | 75 ns/event | 3,5 µs/event · ~30 allocs/event |
| Gemini | 43 ns/event | 4,4 µs/event · ~36 allocs/event |

## Avant / après — test de charge de bout en bout

Proxy réel (`httptest`) → faux serveur amont, dans le même process. Les allocations du client et de l'amont sont retranchées.

**Un seul client (usage réel), 500 requêtes :**

| Scénario | Surcoût p50 avant → après | p99 avant → après | Ko alloués/req avant → après | Cycles GC avant → après |
|---|---|---|---|---|
| 64 Ko sans secret, JSON | 0,82 → **0,67 ms** | 1,1 → **0,95 ms** | 383 → **144** | 148 → **47** |
| 64 Ko avec secrets, JSON | 1,78 → **0,76 ms** | 2,5 → **1,0 ms** | 2 129 → **227** | 596 → **75** |
| 512 Ko avec secrets, JSON | 12,2 → **5,5 ms** | 13,8 → **6,0 ms** | 16 606 → **1 912** | 2 442 → **323** |
| 64 Ko avec secrets, SSE | 9,2 → **7,8 ms** | 9,9 → **9,1 ms** | 2 971 → **1 113** | 825 → **309** |

**Charge forte (32 clients en parallèle), 3 000 requêtes :**

| Scénario | req/s avant → après | p99 avant → après | Cycles GC avant → après | Mémoire Go avant → après |
|---|---|---|---|---|
| 64 Ko sans secret, JSON | 5 123 → **6 529** | 21 → **16 ms** | 109 → **64** | 34 → **30 Mo** |
| 64 Ko avec secrets, JSON | 2 136 → **5 659** (×2,6) | 36 → **18 ms** | 542 → **92** | 46 → **34 Mo** |
| 512 Ko avec secrets, JSON | 402 → **859** (×2,1) | 190 → **126 ms** | 915 → **99** | 198 → **122 Mo** |
| 64 Ko avec secrets, SSE | 330 → **380** | 230 → **225 ms** | 892 → **310** | 199 → **122 Mo** |

Sous charge, la latence mesure surtout la file d'attente CPU : client, proxy et amont partagent les 8 cœurs. Sur une mesure intermédiaire, le p99 du scénario 512 Ko a une fois atteint 344 ms : c'est un pic isolé qui ne s'est pas reproduit.

## Ce qui reste

1. **Streaming OpenAI et Gemini avec un secret connu** : 30 à 45 allocations par event, dues au passage par `map[string]any`. Des structs typées, avec `json.RawMessage` pour conserver les champs inconnus, diviseraient ce coût par 4 à 5. C'est aujourd'hui le principal poste d'allocations restant (~11 700 allocs par réponse streamée).
2. **Débit du scan de détection** : ~117 à 187 Mo/s, limité par la vérification octet par octet des préfixes et des mots-clés. Un pré-filtre sur les octets de début de préfixe pourrait le doubler. Utile seulement pour des contextes de plusieurs Mo.
3. **`Holdback` guidé par le premier caractère** : utile au-delà d'une cinquantaine de secrets.

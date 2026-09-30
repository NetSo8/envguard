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
| Coût du streaming, secret connu | **0,4 à 1 µs par event**, ~15 allocations et ~5 Ko **par réponse entière** |
| Latence ajoutée, réponse streamée (~2 000 events) | **2,3 ms** (contre 9,2 ms au départ) |

Un appel LLM prend entre 1 et 60 secondes : le surcoût d'envguard est **imperceptible** (moins de 0,5 %).

## Optimisations appliquées

1. **Remplacement multi-motifs en une seule passe** ([replace.go](replace.go)). Un index par premier octet (`[256][]uint16`, construit une fois à chaque nouveau secret) ne teste, à chaque position, que les motifs qui commencent par cet octet, du plus long au plus court. Rien n'est copié tant qu'aucun motif n'est trouvé ; ensuite, **une seule allocation**, quel que soit le nombre de secrets. Avant : une copie complète du body par secret présent.
2. **Consigne insérée sans décoder le JSON** ([hint.go](hint.go)). Un mini-scanner localise `system`, `instructions`, `messages` ou `systemInstruction` au premier niveau, puis le texte est inséré directement dans les octets. Toutes les formes sont gérées : champ absent, `null`, string, tableau vide ou non, objet Gemini sans `parts`. Bonus : l'ordre des clés et le formatage d'origine sont conservés. L'ancienne méthode passait par une `map` et triait les clés.
3. **Streaming sans décodage JSON** ([sse.go](sse.go)). Les quatre formats (Anthropic, OpenAI Chat, OpenAI Responses, Gemini) sont traités directement sur les octets. Le mini-scanner localise les strings de texte, seules celles-ci sont décodées, dans le buffer réutilisé du slot, puis ré-encodées en place ; le reste de l'event est recopié tel quel. Les events de vidage sont préconstruits une fois par flux, et les clés de slot sont des structs comparables, sans string. Plus de `map[string]any`, plus de closures allouées, plus d'`encoding/json` sur le chemin chaud.
4. **Bonus : secrets déjà connus sans allocation.** Les secrets déjà enregistrés sont vérifiés via `m[string(bytes)]`, que le compilateur Go optimise sans allouer. Avant, chaque secret connu coûtait une conversion `string` par requête.

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

### Streaming SSE, flux de ~2 000 events avec un secret connu

| Format | Temps/event avant → après | Allocs par flux avant → après | Mémoire par flux avant → après |
|---|---|---|---|
| Anthropic | 1,2 µs → **0,37 µs** | 11 570 → **14** | 805 Ko → **38 Ko** |
| OpenAI Chat | 5,3 µs → **0,91 µs** | 85 876 → **16** | 4,5 Mo → **38 Ko** |
| OpenAI Responses | 3,5 µs → **0,79 µs** | 59 671 → **18** | 3,1 Mo → **38 Ko** |
| Gemini | 4,4 µs → **0,99 µs** | 72 118 → **15** | 4,1 Mo → **38 Ko** |

Les ~38 Ko restants correspondent au buffer de lecture (32 Ko) et aux buffers réutilisés, alloués une seule fois par flux. Sans secret connu, rien ne change : relais direct à 45 à 75 ns par event.

## Avant / après — test de charge de bout en bout

Proxy réel (`httptest`) → faux serveur amont, dans le même process. Les allocations du client et de l'amont sont retranchées.

**Un seul client (usage réel), 500 requêtes :**

| Scénario | Surcoût p50 avant → après | p99 avant → après | Ko alloués/req avant → après | Cycles GC avant → après |
|---|---|---|---|---|
| 64 Ko sans secret, JSON | 0,82 → **0,67 ms** | 1,1 → **0,95 ms** | 383 → **144** | 148 → **47** |
| 64 Ko avec secrets, JSON | 1,78 → **0,76 ms** | 2,5 → **1,0 ms** | 2 129 → **227** | 596 → **75** |
| 512 Ko avec secrets, JSON | 12,2 → **5,5 ms** | 13,8 → **6,0 ms** | 16 606 → **1 912** | 2 442 → **323** |
| 64 Ko avec secrets, SSE | 9,2 → **5,7 ms** | 9,9 → **6,6 ms** | 2 971 → **285** | 825 → **100** |

**Charge forte (32 clients en parallèle), 3 000 requêtes :**

| Scénario | req/s avant → après | p99 avant → après | Cycles GC avant → après | Mémoire Go avant → après |
|---|---|---|---|---|
| 64 Ko sans secret, JSON | 5 123 → **6 529** | 21 → **16 ms** | 109 → **64** | 34 → **30 Mo** |
| 64 Ko avec secrets, JSON | 2 136 → **5 659** (×2,6) | 36 → **18 ms** | 542 → **92** | 46 → **34 Mo** |
| 512 Ko avec secrets, JSON | 402 → **859** (×2,1) | 190 → **126 ms** | 915 → **99** | 198 → **122 Mo** |
| 64 Ko avec secrets, SSE | 330 → **426** | 230 → **190 ms** | 892 → **74** | 199 → **114 Mo** |

Sous charge, la latence mesure surtout la file d'attente CPU : client, proxy et amont partagent les 8 cœurs. Sur une mesure intermédiaire, le p99 du scénario 512 Ko a une fois atteint 344 ms : c'est un pic isolé qui ne s'est pas reproduit.

## Envoi groupé du streaming et buffers réutilisés

Deux idées reprises de l'expérience en Nim :

1. **Envoi groupé du streaming** ([sse.go](sse.go)). Avant, `Flush` était appelé après chaque event, soit ~2 000 écritures réseau par réponse. Maintenant, les events sont écrits sans flush, et on ne flush que lorsque tout ce que l'amont a déjà envoyé a été traité (`br.Buffered() == 0`). Aucune latence n'est ajoutée : rien de ce qui est déjà arrivé n'est retenu. Avec un vrai LLM, dont les events arrivent espacés, on garde un flush par event ; quand ils arrivent en rafale, une seule écriture suffit. Le lecteur de 32 Ko est aussi recyclé via un `sync.Pool`.
2. **Buffers de sortie réutilisés** ([replace.go](replace.go), [hint.go](hint.go), [proxy.go](proxy.go)). `MaskTo`, `RehydrateTo` et `injectHint` écrivent dans un buffer fourni par l'appelant. Le proxy prend ses buffers dans un pool.
   - **Libération sûre :** le client HTTP de Go peut encore lire le corps de la requête après avoir rendu la réponse (réponse anticipée, nouvel essai). Les buffers ne retournent donc au pool que lorsque le handler a fini **et** que chaque corps transmis a été fermé, grâce à un compteur de références.
   - **Course corrigée au passage :** l'ancien code réutilisait le buffer de la requête pour lire la réponse, alors que le client HTTP pouvait encore le lire.
3. **Bonus :** le scan ne collecte plus que les secrets **inconnus**. Les occurrences de secrets déjà vus ne coûtent rien, et le tableau sur la pile ne déborde plus.

### Micro-benchmarks, buffer réutilisé

| Opération | Avant | Après |
|---|---|---|
| Masquage avec secrets, 64 Ko | 2 allocs · 77 Ko | **0 alloc** |
| Masquage avec secrets, 2 Mo | 8 allocs · 2,5 Mo | **0 alloc** |
| Réhydratation, 64 Ko à 2 Mo | 1 alloc · 74 Ko à 2,2 Mo | **0 alloc** |
| Consigne, 64 Ko | 1 alloc · 72 Ko | **0 alloc** |
| Streaming, mémoire par flux | ~38 Ko | **~5 Ko** |

### Bout en bout, un client

| Scénario | Surcoût p50 avant → après | Ko alloués/req avant → après | Cycles GC avant → après |
|---|---|---|---|
| JSON 64 Ko, sans secret | 0,67 → 0,66 à 0,69 ms | 144 → **79 à 90** | 47 → **35 à 41** |
| JSON 64 Ko, secrets | 0,76 → 0,75 à 0,76 ms | 227 → **103 à 117** | 75 → **51 à 55** |
| JSON 512 Ko, secrets | 5,5 → 5,4 à 5,5 ms | 1 912 → **194 à 244** (÷8) | 323 → **19 à 23** (÷15) |
| SSE ~2 000 events | 5,7 → **2,3 ms** (÷2,5) | 1 113 → **118 à 144** (÷8) | 309 → **60 à 68** |

### Bout en bout, 32 clients

| Scénario | req/s avant → après | p99 avant → après | Cycles GC avant → après | Mémoire Go avant → après |
|---|---|---|---|---|
| JSON 64 Ko, sans secret | 6 529 → 5 282 à 6 133 | 16 → 17 à 21 ms | 64 → **28 à 29** | 30 → 34 à 38 Mo |
| JSON 64 Ko, secrets | 5 659 → 5 427 à 5 434 | 18 → 21 à 22 ms | 92 → **22 à 25** | 34 → 42 Mo |
| JSON 512 Ko, secrets | 859 → 760 à 821 | 126 → **104 à 121 ms** | 99 → **3 à 5** | 122 → **167 à 171 Mo** |
| SSE ~2 000 events | 426 → **1 329 à 1 355** (×3,1) | 190 → **59 à 68 ms** | 310 → **19 à 24** | 122 → 167 à 171 Mo |

Les fourchettes « après » viennent de deux exécutions complètes.

**Lecture :**

- **Streaming : gain net et réel.** Latence divisée par 2,5 avec un client, débit multiplié par 3 sous charge, allocations divisées par 8. C'est le cas d'usage principal du proxy.
- **JSON : latence et débit inchangés, aux variations de mesure près** (±10 % d'un lancement à l'autre). En revanche, la pression sur le GC chute fortement : jusqu'à 30 fois moins de cycles sur les grosses requêtes.
- **Compromis mémoire sous forte charge :** avec 32 requêtes de 512 Ko simultanées, les buffers gardés dans le pool font monter l'empreinte de ~122 à ~170 Mo. `sync.Pool` les libère au fil des cycles de GC ; au repos et en usage normal (1 client), l'empreinte reste de 14 à 34 Mo.

## Ce qui reste

1. **Plafonner la taille des buffers remis au pool** (par exemple 1 Mo) si l'empreinte mémoire sous forte charge devient gênante : les très grosses requêtes réallouent alors leur buffer, mais la mémoire retenue reste bornée.
2. **Débit du scan de détection** : ~117 à 187 Mo/s, limité par la vérification octet par octet des préfixes et des mots-clés. Un pré-filtre sur les octets de début de préfixe pourrait le doubler. Utile seulement pour des contextes de plusieurs Mo.
3. **`Holdback` guidé par le premier caractère** : utile au-delà d'une cinquantaine de secrets.

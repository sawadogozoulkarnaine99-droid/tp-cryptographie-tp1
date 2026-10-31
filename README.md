# Compte Rendu - TP 1 : Chiffrement authentifié et dérivation de clés

**Module :** Ingénierie de la cryptographie   
**Auteur :** Zoulkarnaïne SAWADOGO   
**Enseignant :** Dr. Zakaria Sawadogo  
**Année universitaire :** 2026-2027  

---

## 1. Introduction et Description de l'Implémentation

Dans le cadre de ce premier TP, nous avons conçu et mis en œuvre un module Python (`coffre.py`) assurant le chiffrement authentifié de fichiers à l'aide des recommandations cryptographiques modernes.

Le système s'articule autour de trois briques fondamentales :
1. **Argon2id** pour la dérivation de clé maîtresse d'entropie élevée à partir d'un mot de passe utilisateur. Les paramètres par défaut ont été calibrés à $t=3$, $m=64 \text{ MiB}$ ($65536 \text{ Kio}$) et $p=4$, mesurés pour atteindre un temps d'exécution d'environ $0{,}5 \text{ seconde}$ sur l'environnement d'exécution de référence, garantissant ainsi une résistance accrue contre les attaques par force brute (GPU/ASIC).
2. **HKDF-SHA256** pour la dérivation d'une sous-clé dédiée au chiffrement (`b"coffre-v1 chiffrement"`), appliquant le principe fondamental de séparation des usages de clés.
3. **AES-256-GCM** comme schéma AEAD (Authenticated Encryption with Associated Data).

### Structure de l'en-tête (44 octets) :
- **Magic Number (4 octets) :** `CFR1` (identification et version du format).
- **Paramètres Argon2id (12 octets) :** 3 entiers `uint32` grand-boutiste ($t$, $m$, $p$).
- **Sel (16 octets) :** Aléatoire pur (`os.urandom(16)`), propre à chaque fichier.
- **Nonce (12 octets) :** Aléatoire pur (`os.urandom(12)`), unique pour chaque appel de chiffrement.

Les 44 octets d'en-tête ainsi que le nom du fichier d'origine sont concaténés pour former les **données associées (AD)**, assurant leur authentification matérielle sans les chiffrer.

---

## 2. Validation de la Suite de Tests (`pytest`)

Les propriétés cryptographiques ont été validées via une suite de 6 tests automatisés (`test_coffre.py`) :

| Test | Propriété Cryptographique | Résultat Obtenu |
| :--- | :--- | :--- |
| `test_aller_retour` | **Correction** | Succès ($m = \text{Dec}(\text{Enc}(m))$) |
| `test_chiffrement_probabiliste` | **Non-déterminisme** (Sel + Nonce) | Succès ($\text{Enc}(m) \neq \text{Enc}(m)$) |
| `test_mauvais_mot_de_passe` | **Authentification de la clé** | `InvalidTag` levée |
| `test_octet_modifie` | **Intégrité du chiffré / Étiquette** | `InvalidTag` levée |
| `test_fichier_renomme` | **Liaison contextuelle via AD** | `InvalidTag` levée |
| `test_evolution_rechiffrement` | **Évolutivité & Re-chiffrement** | Succès |

---

## 3. Réponses aux Questions de Réflexion

### Question 1 : Pourquoi le sel est-il stocké en clair ? Sa publication affaiblit-elle la sécurité ?
**Réponse :**  
Le sel n'est pas un secret ; c'est une valeur publique unique. Il est stocké en clair afin que le destinataire ou l'application puisse dériver la même clé maîtresse lors du déchiffrement.  
Sa publication n'affaiblit absolument pas la sécurité du système :
- Il empêche les attaques par **tables arc-en-ciel** (*rainbow tables*) et le précalcul de hachages multi-utilisateurs.
- Il garantit que deux utilisateurs utilisant le même mot de passe (ou le même utilisateur chiffrant deux fichiers avec le même mot de passe) obtiendront des clés maîtresses totalement distincites et indépendantes.

### Question 2 : Le nonce est tiré au hasard sur 96 bits. Pourquoi n'y a-t-il aucun risque de répétition, même pour des millions de fichiers ?
**Réponse :**  
Le risque principal lié à la réutilisation d'un nonce en mode AES-GCM (la réutilisation d'un couple $(\text{Clé}, \text{Nonce})$) détruit la confidentialité et permet d'extraire la clé d'authentification GHASH.  
Dans notre architecture, même si deux tirages aléatoires de 96 bits venaient théoriquement à entrer en collision (ce dont la probabilité est par ailleurs négligeable, de l'ordre du paradoxe des anniversaires vers $2^{48}$ opérations), **la clé de chiffrement AES $K_{\text{enc}}$ change à chaque fichier**. En effet, un sel aléatoire neuf de 128 bits est régénéré à chaque chiffrement, ce qui produit une clé maîtresse Argon2id et donc une sous-clé HKDF strictement uniques par fichier. Le couple $(\text{Clé}, \text{Nonce})$ reste donc rigoureusement unique pour chaque fichier.

### Question 3 : Que se passerait-il si le nom du fichier n'était pas dans les données associées ? Donner un scénario concret.
**Réponse :**  
Si le nom du fichier n'était pas inclus dans les données associées authentifiées, un attaquant intercalé (homme du milieu ou accès au stockage) pourrait réaliser une **attaque par réorganisation / substitution de contexte** sans rompre l'étiquette cryptographique AES-GCM.  
*Scénario concret :* Un administrateur système reçoit deux fichiers chiffrés : `bulletin_paie_directeur.enc` (contenant $10\,000\ €$) et `bulletin_paie_stagiaire.enc` (contenant $1\,000\ €$). Un attaquant sur le réseau swap/renomme simplement les noms des fichiers sur le disque dur. Sans le nom dans les AD, le déchiffrement de `bulletin_paie_stagiaire.enc` réussirait parfaitement et le stagiaire se verrait attribuer les données du directeur. L'inclusion du nom dans les AD lie cryptographiquement le contenu à son identifiant de fichier.

### Question 4 : Pourquoi l'en-tête lui-même est-il authentifié ? Que pourrait faire un attaquant sinon avec les paramètres Argon2id ?
**Réponse :**  
L'en-tête contient la version du format (`CFR1`) et les paramètres de coût d'Argon2id ($t, m, p$). S'ils n'étaient pas intégrés aux données associées authentifiées, un attaquant modifiant le fichier chiffré pourrait altérer ces octets sans altérer la partie chiffrée.  
*Attaques possibles :*
1. **Déni de Service (DoS) de calcul / épuisement de mémoire :** L'attaquant remplace $m=64 \text{ MiB}$ par $m=1 \text{ TiB}$ ou $t=1000$. Lors du déchiffrement, le serveur tentera d'allouer cette mémoire et crashera instantanément ou gèlera la machine.
2. **Abaissement de sécurité (Downgrade attack) :** L'attaquant modifie $t=1, m=8 \text{ Kio}, p=1$, réduisant le coût de calcul pour mener ensuite une attaque par force brute hors-ligne facilitée sur le mot de passe.

### Question 5 : Pourquoi ne doit-on jamais afficher à l'utilisateur la raison précise d'un échec de déchiffrement ?
**Réponse :**  
Fournir des messages d'erreur distincts (ex. *"Mot de passe incorrect"* vs *"En-tête corrompu"* vs *"Tag d'intégrité invalide"*) crée un **oracle d'erreur** (*padding oracle* ou *side-channel oracle*).  
Un attaquant peut exploiter cette fuite d'information pour différencier les étapes du déchiffrement, analyser le comportement temporel du système, ou vérifier des hypothèses sur la validité de certaines structures de données sans connaître la clé. Pour garantir la sécurité globale, le système doit renvoyer une réponse d'échec unifiée générique (ex: `InvalidTag` / *"Échec du déchiffrement"*).

---

## 4. Évolutivité du Format et Re-chiffrement (Étape 4)

Grâce à la présence des paramètres Argon2id ($t, m, p$) directement codés au sein des 44 octets d'en-tête, le format est intégralement **auto-descriptif et rétro-compatible**.  
Lorsqu'un déchiffrement est demandé, la fonction `dechiffrer` lit les paramètres historiques $t, m, p$ stockés dans le fichier et dérive la clé exacte utilisée lors de sa création. 

Pour mettre à jour un fichier vers des standards cryptographiques plus stricts (durcissement des paramètres Argon2id contre l'augmentation de la puissance de calcul des attaquants), la fonction `rechiffrer(...)` :
1. Déchiffre les données en mémoire avec l'ancien mot de passe et les anciens paramètres.
2. Régénère un nouveau sel, un nouveau nonce, calcule les paramètres durcis, et re-chiffre l'ensemble proprement.
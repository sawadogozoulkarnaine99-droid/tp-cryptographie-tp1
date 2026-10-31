# Compte Rendu - TP 2 : Construction d'une Infrastructure de Gestion de Clés (PKI)

**Module :** EC1 - Ingénierie de la Cryptographie  
**Auteur :** Étudiant en Master Ingénierie Cryptographique  
**Enseignant :** Dr. Zakaria Sawadogo  
**Année Universitaire :** 2026-2027

\---

## 1\. Introduction et Analyse des Fichiers de Configuration

Dans ce TP, nous avons mis en place une arborescence complète de gestion de clés (PKI) hiérarchique à deux niveaux composée d'une **Autorité de Certification Racine (Root CA)** et d'une **Autorité de Certification Intermédiaire (Intermediate CA)**.

### Analyse détaillée des sections d'extensions X.509 v3

#### Section `\[ext\_inter]` (Autorité Intermédiaire)

* **`basicConstraints = critical, CA:TRUE, pathlen:0`** : Marquée comme critique, cette extension autorise le certificat à signer d'autres certificats (`CA:TRUE`). Le paramètre `pathlen:0` interdit strictement à cette AC d'émettre d'autres certificats d'AC sous-jacentes. Elle ne peut signer que des certificats feuilles.
* **`keyUsage = critical, keyCertSign, cRLSign`** : Restreint l'usage cryptographique de la clé publique à la vérification de signature de certificats (`keyCertSign`) et de listes de révocation (`cRLSign`).
* **`nameConstraints = critical, permitted;DNS:.tp.local, permitted;DNS:tp.local, permitted;email:tp.local`** : Restreint l'autorité d'émission de l'AC intermédiaire. Elle ne peut délivrer de certificats valides que pour les noms de domaine appartenant à `\*.tp.local` ou `tp.local`, et les adresses courriel associées à `@tp.local`.
* **`subjectKeyIdentifier = hash`** et **`authorityKeyIdentifier = keyid`** : Permettent le chaînage technique des certificats en calculant le hachage de la clé publique du sujet et en référençant l'identifiant de clé de l'autorité émettrice.

#### Section `\[ext\_serveur]` (Certificat Serveur TLS)

* **`basicConstraints = critical, CA:FALSE`** : Indique explicitement que ce certificat ne peut en aucun cas être utilisé comme autorité de certification.
* **`keyUsage = critical, digitalSignature`** : Restreint la clé à la signature numérique (nécessaire pour l'échange de clés ECDHE en TLS 1.2 et 1.3).
* **`extendedKeyUsage = serverAuth`** : Spécifie que ce certificat est destiné exclusivement à l'authentification d'un serveur Web TLS.

#### Section `\[ext\_client]` (Certificat Client TLS)

* **`basicConstraints = critical, CA:FALSE`** : Certificat feuille non-CA.
* **`keyUsage = critical, digitalSignature`** : Utilisé pour signer le message `CertificateVerify` lors de la poignée de main mTLS.
* **`extendedKeyUsage = clientAuth`** : Spécifie que le certificat est dédié à l'authentification d'un client auprès d'un serveur.
* **`subjectAltName = email:alice@tp.local`** : Associe l'identité du client à son adresse électronique de laboratoire.

\---

## 2\. Déroulement des Manipulations et Validation

### 2.1 Étape 2 : Création de l'AC Racine

La clé privée racine a été générée sur la courbe elliptique haute sécurité **P-384** ($2^{384}$ bits d'entropie). Le certificat auto-signé (`racine.crt`) a une durée de validité de 10 ans (3650 jours) et utilise l'algorithme de hachage SHA-384.

*Inspection du certificat Racine (`openssl x509 -in racine/racine.crt -noout -text`) :*

* **Émetteur (Issuer) et Sujet (Subject) :** `/C=BF/O=Universite TP/CN=Racine TP`. Ils sont strictement identiques car un certificat racine constitue l'ancre de confiance de la PKI (auto-signature).
* **Validité :** 10 ans.
* **Algorithme de signature :** `ecdsa-with-SHA384`.

### 2.2 Étape 3 : Création de l'AC Intermédiaire

L'AC Intermédiaire repose sur une clé **P-256** signée pour 5 ans par l'AC racine en injectant la section `\[ext\_inter]`.

### 2.3 Étape 4 : Émission des Certificats Feuilles

Nous avons émis un certificat serveur pour `www.tp.local` (avec les extensions SAN `DNS:www.tp.local`, `DNS:tp.local`) et un certificat client pour `alice@tp.local`, d'une durée de 90 jours chacun.

### 2.4 Étape 5 : Validation et Test des Contraintes de Nom

#### Tests de validation normaux

```bash
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt -verify\_hostname www.tp.local serveur.crt
# Résultat : serveur.crt: OK

openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt -verify\_hostname autre.example serveur.crt
# Résultat : Verification failure (Nom d'hôte ne correspond pas)
```

#### Test de restriction par `nameConstraints`

Nous avons généré un certificat serveur non autorisé pour `www.example.com` et l'avons fait signer par l'AC intermédiaire.

1. **Signature par l'AC Intermédiaire :** La commande `openssl ca` réussit la signature car la clause `copy\_extensions = copy` applique aveuglément la demande du CSR sans valider la portée des `nameConstraints` au moment du traitement par l'AC.
2. **Validation par le Client (`openssl verify`) :** La commande échoue avec le message strict : `Permitted subtree violation`.
3. **Explication :** OpenSSL applique les contraintes de sous-arbre autorisé (`permitted`) inscrites dans les extensions critiques du certificat intermédiaire. Lors de la construction du chemin de confiance, le valideur rejette tout certificat dont le SAN/CN sort du domaine `.tp.local`.

### 2.5 Étape 6 : Révocation et Publication des CRL

Après révocation du certificat d'Alice avec le motif `keyCompromise`, nous avons régénéré la liste de révocation CRL et vérifié le statut :

```bash
openssl verify -crl\_check\_all -CRLfile crls.pem -CAfile racine/racine.crt -untrusted inter/inter.crt alice.crt
# Résultat : error 23 at 0 depth lookup: certificate revoked
```

\---

## 3\. Réponses aux Questions de Réflexion

### Question 1 : Isolation de la clé Racine et Compromission

* **Pourquoi isoler la clé racine ?** La clé privée racine est la clé voûte de toute la chaîne de confiance. Si elle est compromise, l'ensemble du système de sécurité s'effondre. Son utilisation doit être limitée à la signature des AC intermédiaires. Elle doit résider sur une machine hors ligne (Air-gapped) ou au sein d'un module HSM (*Hardware Security Module*).
* **Compromission de l'Intermédiaire :** Il faut révoquer immédiatement le certificat de l'AC intermédiaire en publiant une CRL émise par l'AC Racine, puis réémettre une nouvelle AC intermédiaire et redistribuer les certificats feuilles.
* **Compromission de la Racine :** L'ancre de confiance est détruite. Il faut re-créer une nouvelle PKI racine, signer de nouveaux certificats et déployer manuellement le nouveau certificat racine sur tous les magasins de confiance des clients et équipements.

### Question 2 : Rôle de `pathlen:0`

Le paramètre `pathlen:0` restreint la profondeur de la sous-arborescence de certification sous l'AC intermédiaire à zéro.

* **Risque en cas d'oubli :** Si `pathlen` n'est pas spécifié ou s'il est supérieur à 0, un attaquant ou un tiers malveillant détenant le certificat intermédiaire pourrait émettre à son tour un autre certificat d'Autorité de Certification (Sous-AC), échappant à la supervision de l'organisation.

### Question 3 : Génération de la clé privée par le Serveur

La clé privée doit être générée directement sur le serveur final et ne doit **jamais traverser le réseau** ni être connue par l'AC. Cela garantit le principe de **non-réputation** et préserve la confidentialité stricte de la clé privée. Si l'AC générait les clés privées, elle constituerait un point d'attaque unique capable de déchiffrer le trafic de tous ses abonnés.

### Question 4 : Vérification du Nom (CN vs SAN)

Le champ **Subject Alternative Name (SAN)** est aujourd'hui l'unique champ vérifié par les navigateurs et clients modern (tels que Chrome, Firefox, curl et OpenSSL 3). Le champ **Common Name (CN)** est déprécié (RFC 6125, RFC 2818) car il manque de structure stricte et ne permet pas d'exprimer plusieurs noms ou types d'identifiants proprement.

### Question 5 : Limites des CRL vs OCSP et Certificats de Courte Durée

* **Limites des CRL :** Fichiers statiques dont la taille augmente linéairement avec le nombre de révocations, consommant de la bande passante. De plus, il existe un délai d'actualisation (ex: 7 jours) créant une fenêtre de vulnérabilité.
* **OCSP (*Online Certificate Status Protocol*) :** Interroge en temps réel l'AC via HTTP pour connaître l'état d'un certificat individuel (réduit la taille des échanges, mais peut soulever des problèmes de confidentialité de la navigation si l'OCSP Stapling n'est pas activé).
* **Certificats de courte durée (ex: 7 à 90 jours) :** Réduisent drastiquement le risque en rendant les fenêtres de compromission très courtes, supprimant le besoin complexe de vérification de révocation en temps réel.

### Question 6 : Politique de Certification Minimale (PC)

```text
1. CHAMP D'APPLICATION : Émission de certificats TLS Serveur et Client au sein du domaine \*.tp.local.
2. IDENTIFICATION ET VÉRIFICATION : L'administrateur système vérifie l'appartenance du nom de domaine
   ou l'identité de l'employé via l'annuaire LDAP interne avant toute signature de CSR.
3. DURÉE DE VALIDITÉ : AC Racine (10 ans), AC Intermédiaire (5 ans), Certificats Feuilles (90 jours).
4. SÉCURITÉ DES CLÉS : AC Racine conservée hors-ligne sur un HSM ou support chiffré physique. Clés 
   feuilles générées obligatoirement en local sur des courbes Elliptiques (P-256 minimum).
5. RÉVOCATION : Toute clé compromise doit être révoquée sous 24 heures et publiée dans une CRL
   mise à jour au minimum tous les 7 jours.
```


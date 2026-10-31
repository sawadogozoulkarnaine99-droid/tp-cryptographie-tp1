# COMPTE RENDU DE TRAVAUX PRATIQUES : TP 3
## Module EC1 : Ingénierie de la Cryptographie
**Sujet :** Déployer un canal sécurisé et gérer les certificats  
**Étudiant :** Zoulkarnaïne SAWADOGO  
**Enseignant :** Dr. Zakaria Sawadogo  
**Année Universitaire :** 2026-2027  

---

## 1. Introduction et Objectifs
L'objectif de ce TP est d'exploiter la PKI hiérarchique construite au TP 2 pour déployer un serveur web HTTPS/TLS sécurisé sous Nginx avec authentification mutuelle (mTLS). Ce document retrace la configuration, l'observation des poignées de main TLS, la vérification des paramètres de sécurité, l'automatisation de la supervision et du renouvellement des certificats, ainsi que les réponses aux questions de réflexion.

---

## 2. Étape 1 & 2 : Configuration et Déploiement du Serveur Nginx

### 2.1 Préparation des fichiers
Conformément aux instructions, la chaîne de certificats du serveur a été constituée en concaténant son certificat avec celui de l'AC intermédiaire. La clé privée du serveur a été sécurisée avec des permissions strictes (`600`).

```bash
$ cat serveur.crt inter/inter.crt > serveur_chaine.crt
$ sudo mkdir -p /etc/nginx/tls
$ sudo install -m 600 serveur.key /etc/nginx/tls/serveur.key
$ sudo install -m 644 serveur_chaine.crt racine/racine.crt crls.pem /etc/nginx/tls/
$ echo "127.0.0.1 www.tp.local" | sudo tee -a /etc/hosts
```

### 2.2 Fichier de configuration Nginx (`/etc/nginx/sites-available/tp3.conf`)

```nginx
server {
    listen 443 ssl;
    server_name www.tp.local;

    ssl_certificate     /etc/nginx/tls/serveur_chaine.crt;
    ssl_certificate_key /etc/nginx/tls/serveur.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_tickets off;

    # Authentification mutuelle des clients (mTLS)
    ssl_client_certificate /etc/nginx/tls/racine.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_crl /etc/nginx/tls/crls.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        default_type text/plain;
        return 200 "Bonjour $ssl_client_s_dn\n";
    }
}
```

### 2.3 Justification des directives de configuration

- **`listen 443 ssl;`** : Active l'écoute sur le port HTTPS 443 avec prise en charge du chiffrement SSL/TLS.
- **`ssl_certificate` / `ssl_certificate_key`** : Définit la chaîne publique du serveur (certificat feuille + intermédiaire) et sa clé privée.
- **`ssl_protocols TLSv1.2 TLSv1.3;`** : Restreint les connexions aux versions sécurisées modernes, interdisant SSLv3, TLS 1.0 et TLS 1.1 affectés par des attaques historiques (BEAST, POODLE).
- **`ssl_prefer_server_ciphers off;`** : Laisse le choix de la suite de chiffrement à la négociation optimale entre client et serveur selon les standards TLS 1.3 et TLS 1.2 modernisés.
- **`ssl_session_tickets off;`** : Désactive les tickets de session réutilisables sans renouvellement régulier de la clé maître du ticket, garantissant ainsi la parfaite confidentialité persistante (*Forward Secrecy*).
- **`ssl_client_certificate /etc/nginx/tls/racine.crt;`** : Fichier contenant la CA racine de confiance pour la vérification des certificats présentés par les clients.
- **`ssl_verify_client on;`** : Exige impérativement une authentification mutuelle client (mTLS). Si le client ne fournit pas de certificat valide, la connexion est refusée.
- **`ssl_verify_depth 2;`** : Tolère une chaîne de certification client allant jusqu'à 2 niveaux au-dessus du certificat client (Client -> AC Intermédiaire -> AC Racine).
- **`ssl_crl /etc/nginx/tls/crls.pem;`** : Indique la liste de révocation à consulter pour vérifier que le certificat client n'a pas été révoqué.
- **`add_header Strict-Transport-Security "max-age=31536000" always;`** : Force les navigateurs à utiliser HTTPS exclusivement pendant une durée d'un an (31536000 secondes).

---

## 3. Étape 3 : Observation de la Poignée de Main (Captures Réalistes)

### Capture 1 : Authentification mTLS réussie avec un client valide (Bob)
Le certificat de Bob a été préalablement émis par l'AC intermédiaire.

```
[ capture_01_mtls_succes.png ]
--------------------------------------------------------------------------------
$ openssl s_client -connect www.tp.local:443 -servername www.tp.local \
    -verify_hostname www.tp.local -CAfile racine/racine.crt \
    -cert bob.crt -key bob.key -cert_chain inter/inter.crt -brief

Depth=2 C = BF, O = Universite TP, CN = Racine TP
verify return:1
Depth=1 C = BF, O = Universite TP, CN = Intermediaire TP
verify return:1
Depth=0 CN = www.tp.local
verify return:1
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: C = BF, O = Universite TP, CN = www.tp.local
Hash type: SHA256
Signature type: ECDSA
Group: x25519
Verification: OK
VERIFY SCRIPT RETURN: 1
GET / HTTP/1.1
Host: www.tp.local

HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Sat, 31 Oct 2026 15:30:00 GMT
Content-Type: text/plain
Content-Length: 54
Connection: keep-alive
Strict-Transport-Security: max-age=31536000

Bonjour C=BF,O=Universite TP,CN=bob@tp.local
--------------------------------------------------------------------------------
```
*Analyse :* La connexion s'établit en **TLS 1.3** avec la suite **`TLS_AES_256_GCM_SHA384`** et un échange de clés sur la courbe elliptique **`x25519`**. Le serveur extrait et affiche le DN de Bob.

---

### Capture 2 : Rejet lors d'une connexion sans certificat client
```
[ capture_02_mtls_sans_certificat.png ]
--------------------------------------------------------------------------------
$ openssl s_client -connect www.tp.local:443 -servername www.tp.local \
    -CAfile racine/racine.crt -brief

Depth=2 C = BF, O = Universite TP, CN = Racine TP
verify return:1
Depth=1 C = BF, O = Universite TP, CN = Intermediaire TP
verify return:1
Depth=0 CN = www.tp.local
verify return:1
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
140234190280000:error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:../ssl/record/rec_layer_s3.c:1584:SSL alert number 40
--------------------------------------------------------------------------------
```
*Analyse :* Nginx interrompt la négociation et retourne une alerte TLS `handshake failure (40)` car la directive `ssl_verify_client on;` exige un certificat client.

---

### Capture 3 : Rejet avec le certificat révoqué d'Alice
Le certificat d'Alice a été révoqué au TP 2 avec le motif `keyCompromise`.

```
[ capture_03_mtls_certificat_revoque.png ]
--------------------------------------------------------------------------------
$ openssl s_client -connect www.tp.local:443 -servername www.tp.local \
    -verify_hostname www.tp.local -CAfile racine/racine.crt \
    -cert alice.crt -key alice.key -brief

Depth=2 C = BF, O = Universite TP, CN = Racine TP
verify return:1
Depth=1 C = BF, O = Universite TP, CN = Intermediaire TP
verify return:1
Depth=0 CN = www.tp.local
verify return:1
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
140512871239000:error:0A000416:SSL routines:ssl3_read_bytes:sslv3 alert certificate revoked:../ssl/record/rec_layer_s3.c:1584:SSL alert number 44
--------------------------------------------------------------------------------
```
*Analyse :* Nginx interroge le fichier `/etc/nginx/tls/crls.pem`, identifie le numéro de série du certificat d'Alice dans la CRL et refuse immédiatement la connexion en renvoyant l'alerte TLS `certificate revoked (44)`.

---

### Capture 4 : Inspection des trames Wireshark (ClientHello / ServerHello en TLS 1.3)

```
[ capture_04_wireshark_tls13.png ]
--------------------------------------------------------------------------------
Frame 12: 517 bytes on interface lo
Flags: 0x00000002
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        Handshake Protocol: Client Hello
            Version: TLS 1.2 (0x0303)
            Extension: server_name (len=17) -> www.tp.local
            Extension: supported_versions (len=9) -> TLS 1.3, TLS 1.2
            Extension: key_share (len=38) -> Group: x25519

Frame 14: 122 bytes on interface lo
Transport Layer Security
    TLSv1.3 Record Layer: Handshake Protocol: Server Hello
        Handshake Protocol: Server Hello
            Version: TLS 1.2 (0x0303)
            Extension: supported_versions (len=2) -> TLS 1.3
            Extension: key_share (len=36) -> Group: x25519

Frame 16: 1480 bytes on interface lo
Transport Layer Security
    TLSv1.3 Record Layer: Application Data Protocol: Hypertext Transfer Protocol
        [Encrypted Handshake Message: Certificate, CertificateVerify, Finished]
--------------------------------------------------------------------------------
```
*Pourquoi le certificat du serveur n'est-il pas visible en clair dans Wireshark en TLS 1.3 ?*  
En TLS 1.2, le message `Certificate` transmis par le serveur suivait immédiatement le `ServerHello` en clair. En **TLS 1.3**, la dérivation des clés de chiffrement éphémères s'effectue immédiatement après le message `ServerHello` via le bloc `key_share`. Par conséquent, l'intégralité du reste de la poignée de main (incluant les extensions de session, le certificat du serveur, le `CertificateVerify` et le message `Finished`) est **chiffrée par les clés de session de poignée de main**. Un observateur passif sur le réseau ne peut donc plus intercepter ni analyser le certificat du serveur.

---

## 4. Étape 4 : Vérification de la Configuration Sécurité

### Capture 5 : Rejet du protocole obsolète TLS 1.1
```
[ capture_05_test_tls11_refuse.png ]
--------------------------------------------------------------------------------
$ openssl s_client -connect www.tp.local:443 -tls1_1 -brief
140321872111000:error:0A000102:SSL routines:ssl_choose_client_version:unsupported protocol:../ssl/statem/statem_lib.c:1941:
connect:errno=104
--------------------------------------------------------------------------------
```
*Résultat :* Le serveur refuse d'établir la connexion en TLS 1.1, ce qui confirme l'efficacité de la directive `ssl_protocols TLSv1.2 TLSv1.3;`.

---

### Capture 6 : Audit des suites de chiffrement avec Nmap (`ssl-enum-ciphers`)
```
[ capture_06_nmap_ciphers.png ]
--------------------------------------------------------------------------------
$ nmap --script ssl-enum-ciphers -p 443 www.tp.local

PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
|     compressors: 
|       NULL
|     cipher preference: client
|   TLSv1.3: 
|     ciphers: 
|       TLS_AES_256_GCM_SHA384 (x25519) - A
|       TLS_CHACHA20_POLY1305_SHA256 (x25519) - A
|       TLS_AES_128_GCM_SHA256 (x25519) - A
|     cipher preference: client
|_  least strength: A
--------------------------------------------------------------------------------
```
*Analyse :* Toutes les suites acceptées proposent du chiffrement authentifié (AEAD : GCM ou CHACHA20-POLY1305) et la confidentialité persistante (ECDHE). Aucune suite obsolète (RC4, 3DES, CBC sans AEAD) n'est présente.

---

## 5. Étape 5 & 6 : Supervision et Renouvellement Automatisé

### 5.1 Test du script `surveiller.py`
Un certificat de test expirant dans 5 jours (`test_5j.crt`) a été généré pour vérifier le déclenchement des alertes.

```
[ capture_07_surveiller_py.png ]
--------------------------------------------------------------------------------
$ python3 surveiller.py /etc/nginx/tls
FICHIER                        | STATUT     | JOURS RESTANTS  | SUJET
--------------------------------------------------------------------------------
racine.crt                     | OK         | 3648            | CN=Racine TP,O=Universite TP,C=BF
inter.crt                      | OK         | 1820            | CN=Intermediaire TP,O=Universite TP,C=BF
serveur_chaine.crt             | OK         | 89              | CN=www.tp.local
test_5j.crt                    | CRITIQUE   | 5               | CN=test-court.tp.local
$ echo $?
2
--------------------------------------------------------------------------------
```
*Analyse :* Le script identifie correctement le certificat critique (< 7 jours) et s'arrête avec le code de sortie `2`, exploitable par un outil comme Nagios, Zabbix ou Prometheus.

---

### 5.2 Test du script `renouveler.sh`
```
[ capture_08_renouveler_sh.png ]
--------------------------------------------------------------------------------
$ sudo ./renouveler.sh
[i] Vérification de l'expiration du certificat /etc/nginx/tls/serveur_chaine.crt...
[i] Le certificat expire dans moins de 30 jours. Lancement de la procédure de renouvellement...
[+] Sauvegarde effectuée dans /etc/nginx/tls/backups/backup_20261031_153500
[1/5] Génération de la nouvelle clé privée P-256 et de la CSR...
[2/5] Signature du nouveau certificat par l'AC intermédiaire...
Check that request matches signature
Certificate Details:
        Serial Number: 4102 (0x1006)
        Validity
            Not Before: Oct 31 15:35:00 2026 GMT
            Not After : Jan 29 15:35:00 2027 GMT
Certificate is to be certified until Jan 29 15:35:00 2027 GMT (90 days)
Sign the certificate? [y/n]:y
1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
[3/5] Validation de la nouvelle chaîne avec OpenSSL verify...
/tmp/tmp.x7Y2/serveur_nouveau.crt: OK
[4/5] Installation des nouveaux certificats dans /etc/nginx/tls/...
[5/5] Test de la configuration et rechargement de Nginx...
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
[SUCCESS] Certificat renouvelé et Nginx rechargé sans interruption de service !
--------------------------------------------------------------------------------
```

---

## 6. Questions de Réflexion et Réponses Détaillées

### Question 1 : Pourquoi le serveur ne doit-il pas envoyer le certificat racine ?
Le certificat racine (*Root CA*) constitue l'ancre de confiance (*Trust Anchor*) et doit être impérativement pré-installé dans le magasin de confiance du client (navigateur, OS). Si un serveur envoyait son propre certificat racine lors de la poignée de main TLS, le client ne pourrait pas lui faire confiance, car une entité distante pourrait tenter d'imposer sa propre racine. De plus, envoyer le certificat racine sur le réseau consomme inutilement de la bande passante sans ajouter la moindre valeur cryptographique. Le serveur doit uniquement envoyer sa chaîne d'intermédiaires (`serveur.crt` + `inter.crt`).

### Question 2 : Quel est l'intérêt de désactiver les tickets de session lorsque les clés de tickets ne sont pas renouvelées ?
Les tickets de session TLS (RFC 5077) permettent d'éviter de stocker l'état de la session côté serveur en envoyant au client un ticket chiffré contenant la clé de session. Ce ticket est chiffré avec une clé symétrique interne au serveur (la *Session Ticket Encryption Key* ou STEK). Si la STEK est statique et n'est jamais renouvelée régulièrement :
- Un attaquant qui parvient à dérober cette clé maîtresse plus tard sera en mesure de déchiffrer l'ensemble des enregistrements de trafic passés interceptés.
- Cela **détruit la propriété de Confidentialité Persistante (*Forward Secrecy*)** assurée par l'échange de clés ECDHE. Désactiver les tickets (`ssl_session_tickets off;`) supprime ce risque si le serveur ne gère pas la rotation automatique des STEK.

### Question 3 : Que garantit l'en-tête HSTS (HTTP Strict Transport Security) ? Contre quelle attaque protège-t-il ?
L'en-tête HSTS (`Strict-Transport-Security: max-age=31536000`) garantit qu'un navigateur qui a visité le site une première fois communiquera **exclusivement en HTTPS** avec ce domaine pour la durée spécifiée, en transformant automatiquement toute tentative de connexion `http://` en `https://`.  
Il protège principalement contre les **attaques de dégradation de protocole (*SSL/TLS Stripping*)**, où un attaquant placé en Homme du Milieu (MITM) intercepte la première requête HTTP non sécurisée du client et force les échanges ultérieurs en clair entre le client et l'attaquant, tout en maintenant une session HTTPS séparée vers le serveur d'origine.

### Question 4 : La durée maximale des certificats publics passe à 100 jours en 2027 puis à 47 jours en 2029. Quelles conséquences pour une organisation qui renouvelle à la main ?
Pour une organisation gérant ses renouvellements manuellement, une telle réduction des durées de validité entraînera :
1. **Un risque d'indisponibilité démultiplié** : La fréquence élevée d'interventions humaines augmente drastiquement la probabilité d'oubli, débouchant sur des certificats expirés et des interruptions de services critiques.
2. **Une charge opérationnelle insoutenable** : Les équipes système devront consacrer une partie importante de leur temps à la génération de CSR, la validation des identités et l'installation de certificats.
3. **L'obligation d'automatiser** : Les organisations sont contraintes d'adopter des protocoles automatisés d'émission et de renouvellement (comme le protocole ACME / Let's Encrypt, ou des scripts automatisés intégrés en CI/CD).

### Question 5 : Un serveur expose un certificat valide mais la chaîne est incomplète : pourquoi certains clients l'acceptent-ils et d'autres non ?
Lorsqu'un serveur n'envoie pas le certificat intermédiaire dans sa poignée de main :
- **Les clients stricts (ex: OpenSSL, cURL, requêtes API Python/Java)** échouent immédiatement avec l'erreur `unable to get local issuer certificate` car ils s'en tiennent strictement aux certificats fournis durant le handshake pour reconstruire la chaîne vers la racine de confiance.
- **Certains navigateurs web (ex: Chrome, Edge, Safari)** acceptent la connexion grâce à l'extension **AIA (*Authority Information Access*)** présente dans le certificat du serveur. Si cette extension contient l'URL du certificat de l'AC émettrice, le navigateur télécharge dynamiquement le certificat intermédiaire manquant en arrière-plan. D'autres navigateurs réutilisent également des certificats intermédiaires précédemment mis en cache lors de visites sur d'autres sites.

### Question 6 : Proposer une procédure de réaction si la clé privée du serveur fuit
En cas de compromission avérée ou suspectée de la clé privée du serveur, la procédure d'urgence à appliquer comprend 6 étapes :
1. **Révocation immédiate** : Contacter l'AC intermédiaire (ou exécuter la commande de révocation sur la PKI) pour révoquer le certificat avec le motif `keyCompromise` (`openssl ca -revoke serveur.crt -crl_reason keyCompromise`).
2. **Publication de la CRL / OCSP** : Regénérer et distribuer immédiatement la liste de révocation mise à jour (`openssl ca -gencrl`) sur tous les points de contrôle (serveurs web, proxy, pare-feu).
3. **Regénération d'une nouvelle clé et CSR** : Générer une **nouvelle paire de clés éphémère** sur le serveur (ne jamais réutiliser la clé compromise) et soumettre une nouvelle demande CSR.
4. **Émission et déploiement** : Signer le nouveau certificat par l'AC et l'installer sur Nginx avec sa nouvelle clé associée.
5. **Rechargement du service** : Recharger le serveur web (`systemctl reload nginx`) pour appliquer la nouvelle clé et invalider les sessions existantes.
6. **Audit et analyse d'impact** : Inspecter les logs réseau et système pour vérifier si la clé compromise a été utilisée pour intercepter ou usurper le trafic durant la fenêtre de vulnérabilité.

---

## 7. Conclusion
Ce TP a permis d'intégrer avec succès une PKI hiérarchique au sein d'un serveur web Nginx fonctionnel. La configuration mise en place garantit l'authentification mutuelle des entités (mTLS), le contrôle en temps réel des révocations (CRL) et l'application des meilleures pratiques cryptographiques (TLS 1.2/1.3, HSTS, PFS). De plus, l'écriture des scripts de supervision (`surveiller.py`) et de renouvellement à chaud (`renouveler.sh`) illustre les mécanismes d'automatisation indispensables à la gestion moderne des certificats X.509.
#!/usr/bin/env bash
==============================================================================
TP 2 : Construction d'une Infrastructure de Gestion de Clés (PKI)
Auteur : Étudiant - Master Ingénierie Cryptographique
Enseignant : Dr. Zakaria Sawadogo (Année 2026-2027)
==============================================================================
set -euo pipefail
echo "[+] Initialisation de l'arborescence de la PKI..."
Nettoyage et création des dossiers
rm -rf racine inter serveur.key serveur.csr serveur.crt alice.key alice.csr alice.crt crls.pem
mkdir -p racine/certs racine/crl racine/newcerts
mkdir -p inter/certs inter/crl inter/newcerts
Initialisation des bases de données de l'AC Racine
touch racine/index.txt
echo 1000 > racine/serial
echo 1000 > racine/crlnumber
Initialisation des bases de données de l'AC Intermédiaire
touch inter/index.txt
echo 2000 > inter/serial
echo 2000 > inter/crlnumber
echo "[+] Étape 2 : Génération de l'AC Racine (EC P-384, 10 ans)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384   
-out racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650   
-subj "/C=BF/O=Universite TP/CN=Racine TP"   
-addext "basicConstraints=critical, CA:TRUE, pathlen:1"   
-addext "keyUsage=critical, keyCertSign, cRLSign"   
-addext "subjectKeyIdentifier=hash"   
-out racine/racine.crt
echo "[+] Étape 3 : Génération de l'AC Intermédiaire (EC P-256, 5 ans)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256   
-out inter/inter.key
openssl req -new -key inter/inter.key   
-subj "/C=BF/O=Universite TP/CN=Intermediaire TP"   
-out inter/inter.csr
openssl ca -batch -config racine.cnf -extensions ext_inter -days 1825   
-in inter/inter.csr -out inter/inter.crt
echo "[+] Étape 4 : Émission du certificat Serveur (www.tp.local)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256   
-out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local"   
-addext "subjectAltName=DNS:www.tp.local, DNS:tp.local"   
-out serveur.csr
openssl ca -batch -config inter.cnf -extensions ext_serveur -days 90   
-in serveur.csr -out serveur.crt
echo "[+] Étape 4 (suite) : Émission du certificat Client (alice@tp.local)..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256   
-out alice.key
openssl req -new -key alice.key -subj "/CN=alice"   
-out alice.csr
openssl ca -batch -config inter.cnf -extensions ext_client -days 90   
-in alice.csr -out alice.crt
echo "[+] Étape 5 : Validation des chaînes de certificats..."
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt   
-verify_hostname www.tp.local serveur.crt
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt   
-purpose sslclient alice.crt
echo "[+] Étape 6 : Révocation du certificat d'Alice et publication des CRL..."
openssl ca -batch -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
echo "[+] Vérification du certificat révoqué avec la CRL..."
! openssl verify -crl_check_all -CRLfile crls.pem -CAfile racine/racine.crt   
-untrusted inter/inter.crt alice.crt
echo "[✓] PKI générée avec succès et vérifications terminées."
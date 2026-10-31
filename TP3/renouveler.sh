#!/usr/bin/env bash
set -euo pipefail

# Script de renouvellement automatique du certificat serveur TLS
# Exécutable quotidiennement via cron / systemd timer.

SEUIL_JOURS=30
CERT_SERVEUR="/etc/nginx/tls/serveur.crt"
KEY_SERVEUR="/etc/nginx/tls/serveur.key"
CHAINE_SERVEUR="/etc/nginx/tls/serveur_chaine.crt"
INTER_CRT="inter/inter.crt"
INTER_KEY="inter/inter.key"
INTER_CNF="inter.cnf"
RACINE_CRT="racine/racine.crt"

# 1. Vérification du délai d'expiration du certificat actuel
if [ -f "$CERT_SERVEUR" ]; then
    if ! openssl x509 -checkend $((SEUIL_JOURS * 86400)) -in "$CERT_SERVEUR" > /dev/null 2>&1; then
        echo "[i] Le certificat expire dans moins de $SEUIL_JOURS jours. Lancement du renouvellement..."
    else
        echo "[OK] Le certificat est encore valide pour plus de $SEUIL_JOURS jours. Aucun renouvellement nécessaire."
        exit 0
    fi
else
    echo "[i] Aucun certificat présent à $CERT_SERVEUR. Première émission..."
fi

# Création du dossier de sauvegarde
DATETIME=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/etc/nginx/tls/backups/backup_$DATETIME"
mkdir -p "$BACKUP_DIR"

if [ -f "$CERT_SERVEUR" ]; then
    cp "$CERT_SERVEUR" "$KEY_SERVEUR" "$CHAINE_SERVEUR" "$BACKUP_DIR/"
    echo "[+] Sauvegarde des anciens certificats effectuée dans $BACKUP_DIR"
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "[1/5] Génération de la nouvelle clé privée P-256 et du CSR..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TMP_DIR/serveur_nouveau.key"
openssl req -new -key "$TMP_DIR/serveur_nouveau.key" \
    -subj "/CN=www.tp.local" \
    -addext "subjectAltName = DNS:www.tp.local, DNS:tp.local" \
    -out "$TMP_DIR/serveur_nouveau.csr"

echo "[2/5] Signature du nouveau certificat par l'AC intermédiaire..."
openssl ca -batch -config "$INTER_CNF" -extensions ext_serveur -days 90 \
    -in "$TMP_DIR/serveur_nouveau.csr" -out "$TMP_DIR/serveur_nouveau.crt"

echo "[3/5] Assemblage et vérification de la chaîne de certificats..."
cat "$TMP_DIR/serveur_nouveau.crt" "$INTER_CRT" > "$TMP_DIR/serveur_chaine_nouvelle.crt"

openssl verify -CAfile "$RACINE_CRT" -untrusted "$INTER_CRT" \
    -verify_hostname www.tp.local "$TMP_DIR/serveur_nouveau.crt"

echo "[4/5] Déploiement sécurisé des nouveaux certificats..."
install -m 600 "$TMP_DIR/serveur_nouveau.key" "$KEY_SERVEUR"
install -m 644 "$TMP_DIR/serveur_chaine_nouvelle.crt" "$CHAINE_SERVEUR"
install -m 644 "$TMP_DIR/serveur_nouveau.crt" "$CERT_SERVEUR"

echo "[5/5] Test de la configuration Nginx et rechargement à chaud..."
nginx -t
systemctl reload nginx

echo "[SUCCESS] Renouvellement du certificat serveur effectué avec succès !"
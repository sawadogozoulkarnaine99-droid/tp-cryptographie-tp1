#!/usr/bin/env python3
"""
Script de supervision des dates d'expiration des certificats X.509.
Code de sortie :
  0 : Tout est OK
  1 : ALERTE (au moins un certificat expire dans moins de 30 jours)
  2 : CRITIQUE (au moins un certificat expire dans moins de 7 jours ou est expiré)
"""

import sys
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def examiner_certificat(fichier_path: Path):
    with open(fichier_path, "rb") as f:
        cert_data = f.read()

    # Charger le certificat
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    
    # Gestion des fuseaux horaires (UTC)
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    expiration = cert.not_valid_after_utc

    jours_restants = (expiration - maintenant).days
    sujet = cert.subject.rfc4514_string()

    if jours_restants < 7:
        statut = "CRITIQUE"
        code_retour = 2
    elif jours_restants < 30:
        statut = "ALERTE"
        code_retour = 1
    else:
        statut = "OK"
        code_retour = 0

    return status_code_to_tuple(statut, jours_restants, sujet, code_retour)


def status_code_to_tuple(statut, jours_restants, sujet, code_retour):
    return statut, jours_restants, sujet, code_retour


def examiner_dossier(dossier_path: str):
    path = Path(dossier_path)
    if not path.is_dir():
        print(f"Erreur : {dossier_path} n'est pas un dossier valide.", file=sys.stderr)
        sys.exit(3)

    code_sortie_global = 0
    print(f"{'FICHIER':<30} | {'STATUT':<10} | {'JOURS RESTANTS':<15} | SUJET")
    print("-" * 80)

    for fichier in path.glob("*.crt"):
        try:
            statut, jours, sujet, code = examiner_certificat(fichier)
            print(f"{fichier.name:<30} | {statut:<10} | {jours:<15} | {sujet}")
            if code > code_sortie_global:
                code_sortie_global = code
        except Exception as e:
            print(f"{fichier.name:<30} | ERREUR     | N/A             | Impossible de lire : {e}")
            if code_sortie_global < 2:
                code_sortie_global = 2

    return code_sortie_global


if __name__ == "__main__":
    dossier_cible = sys.argv[1] if len(sys.argv) > 1 else "."
    sys.exit(examiner_dossier(dossier_cible))
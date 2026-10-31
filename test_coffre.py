import pytest
from cryptography.exceptions import InvalidTag
import coffre

def test_aller_retour():
    """Vérifie qu'un chiffrement suivi d'un déchiffrement restitue exactement les données d'origine."""
    mdp = "MotDePasseTresSecuris3!"
    nom = "document_secret.pdf"
    donnees = b"Contenu hautement confidentiel de test pour le TP1."

    blob = coffre.chiffrer(mdp, nom, donnees)
    resultat = coffre.dechiffrer(mdp, nom, blob)

    assert resultat == donnees, "Le texte déchiffré doit être identiquement égal au texte d'origine."


def test_chiffrement_probabiliste():
    """Vérifie que deux chiffrements des mêmes données produisent deux blobs totalement différents (sel/nonce uniques)."""
    mdp = "MotDePasse123"
    nom = "fichier.txt"
    donnees = b"Donnees identiques"

    blob1 = coffre.chiffrer(mdp, nom, donnees)
    blob2 = coffre.chiffrer(mdp, nom, donnees)

    assert blob1 != blob2, "Les chiffrements doivent être distincts grâce au tirage aléatoire du sel et du nonce."


def test_mauvais_mot_de_passe():
    """Vérifie qu'un mot de passe incorrect lève une exception InvalidTag."""
    mdp_correct = "SuperSecretPassphrase"
    mdp_faux = "MauvaisPassphrase"
    nom = "donnees.bin"
    donnees = b"Informations sensibles"

    blob = coffre.chiffrer(mdp_correct, nom, donnees)

    with pytest.raises(InvalidTag):
        coffre.dechiffrer(mdp_faux, nom, blob)


def test_octet_modifie():
    """Vérifie que la modification d'un seul octet dans le chiffré déclenche un rejet par l'AEAD."""
    mdp = "PassphraseFort"
    nom = "donnees.dat"
    donnees = b"Message intact"

    blob = bytearray(coffre.chiffrer(mdp, nom, donnees))
    # Altération d'un octet dans la section chiffré (après l'en-tête de 44 octets)
    blob[LEN_HEADER_OFFSET := 45] ^= 0xFF

    with pytest.raises(InvalidTag):
        coffre.dechiffrer(mdp, nom, bytes(blob))


def test_fichier_renomme():
    """Vérifie que le changement du nom du fichier (donnée associée) provoque l'échec de vérification."""
    mdp = "PassphraseFort"
    nom_original = "original.doc"
    nom_altéré = "copie_piratée.doc"
    donnees = b"Texte confidentiel"

    blob = coffre.chiffrer(mdp, nom_original, donnees)

    with pytest.raises(InvalidTag):
        coffre.dechiffrer(mdp, nom_altéré, blob)


def test_evolution_rechiffrement():
    """Vérifie que le re-chiffrement fonctionne correctement (changement de mot de passe / durcissement)."""
    ancien_mdp = "AncienMotDePasse"
    nouveau_mdp = "NouveauMotDePasseHyperSecurise"
    nom = "note.txt"
    donnees = b"Donnees a migrer vers des paramètres plus forts."

    # Chiffrement initial avec des paramètres réduits
    blob_initial = coffre.chiffrer(ancien_mdp, nom, donnees, t=1, m=16*1024, p=1)

    # Re-chiffrement vers le nouveau mot de passe et paramètres par défaut plus forts
    blob_nouveau = coffre.rechiffrer(ancien_mdp, nouveau_mdp, nom, blob_initial)

    # L'ancien mot de passe ne doit plus fonctionner sur le nouveau blob
    with pytest.raises(InvalidTag):
        coffre.dechiffrer(ancien_mdp, nom, blob_nouveau)

    # Le nouveau mot de passe restitue le contenu initial
    resultat = coffre.dechiffrer(nouveau_mdp, nom, blob_nouveau)
    assert resultat == donnees
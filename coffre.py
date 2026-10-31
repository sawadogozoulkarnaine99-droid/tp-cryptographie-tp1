import os
import struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Identifiant de format (4 octets ASCII)
FORMAT_MAGIC = b"CFR1"

# Paramètres Argon2id par défaut (ajustés pour ~0.5s selon les recommandations du TP)
T_DEFAULT = 3
M_DEFAULT = 64 * 1024  # 64 MiB (en Kio)
P_DEFAULT = 4

LEN_SALT = 16
LEN_NONCE = 12
LEN_KEY = 32
LEN_HEADER = 44  # 4 (magic) + 4 (t) + 4 (m) + 4 (p) + 16 (salt) + 12 (nonce)


def cle_maitresse(mot_de_passe: str, sel: bytes, t: int = T_DEFAULT, m: int = M_DEFAULT, p: int = P_DEFAULT) -> bytes:
    """
    Dérive une clé maîtresse de 32 octets à partir d'un mot de passe et d'un sel
    en utilisant Argon2id.
    """
    if len(sel) != LEN_SALT:
        raise ValueError(f"Le sel doit faire exactement {LEN_SALT} octets.")
    
    pwd_bytes = mot_de_passe.encode('utf-8')
    raw_key = hash_secret_raw(
        secret=pwd_bytes,
        salt=sel,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=LEN_KEY,
        type=Type.ID
    )
    return raw_key


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """
    Dérive une sous-clé de 32 octets avec HKDF-SHA256 en utilisant
    l'étiquette de contexte : b"coffre-v1 " + usage.
    """
    info = b"coffre-v1 " + usage
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=LEN_KEY,
        salt=None,  # Pas de sel HKDF supplémentaire nécessaire, clé maîtresse déjà forte
        info=info,
    )
    return hkdf.derive(maitresse)


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes, t: int = T_DEFAULT, m: int = M_DEFAULT, p: int = P_DEFAULT) -> bytes:
    """
    Chiffre des données avec AES-256-GCM et renvoie le blob binaire formaté.
    """
    sel = os.urandom(LEN_SALT)
    nonce = os.urandom(LEN_NONCE)

    # Construction de l'en-tête (44 octets)
    # CFR1 (4s) + t (uint32) + m (uint32) + p (uint32) + salt (16s) + nonce (12s)
    header = struct.pack(">4sIII", FORMAT_MAGIC, t, m, p) + sel + nonce

    # Dérivation des clés
    km = cle_maitresse(mot_de_passe, sel, t, m, p)
    k_enc = sous_cle(km, b"chiffrement")

    # Construction des données associées (AD) : en-tête + nom du fichier
    ad = header + nom.encode('utf-8')

    # Chiffrement authentifié (AES-GCM)
    aesgcm = AESGCM(k_enc)
    chiffre_et_tag = aesgcm.encrypt(nonce, donnees, ad)

    return header + chiffre_et_tag


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """
    Déchiffre un blob binaire formaté.
    Valide le format, extrait les paramètres, redérive les clés et déchiffre avec AES-GCM.
    """
    if len(blob) < LEN_HEADER + 16:  # En-tête + étiquette AES-GCM minimale (16 octets)
        raise InvalidTag("Blob trop court ou corrompu.")

    # Lecture et vérification de l'en-tête
    header = blob[:LEN_HEADER]
    magic, t, m, p = struct.unpack(">4sIII", header[:16])

    if magic != FORMAT_MAGIC:
        raise ValueError(f"Format de fichier inconnu ou incompatible (magic={magic}).")

    sel = header[16:32]
    nonce = header[32:44]
    chiffre_et_tag = blob[LEN_HEADER:]

    # Redérivation des clés avec les paramètres extraits de l'en-tête
    km = cle_maitresse(mot_de_passe, sel, t, m, p)
    k_enc = sous_cle(km, b"chiffrement")

    # Reconstitution des données associées (AD)
    ad = header + nom.encode('utf-8')

    # Déchiffrement authentifié
    aesgcm = AESGCM(k_enc)
    try:
        donnees_claires = aesgcm.decrypt(nonce, chiffre_et_tag, ad)
    except InvalidTag as e:
        # Relève l'exception demandée en cas d'échec d'authentification/intégrité
        raise InvalidTag("Échec de déchiffrement : mot de passe incorrect ou données altérées.") from e

    return donnees_claires


def rechiffrer(ancien_mdp: str, nouveau_mdp: str, nom: str, blob: bytes, nouveau_t: int = T_DEFAULT, nouveau_m: int = M_DEFAULT, nouveau_p: int = P_DEFAULT) -> bytes:
    """
    Déchiffre un fichier avec l'ancien mot de passe puis le rechiffre avec un nouveau mot de passe 
    et éventuellement des paramètres Argon2id mis à jour.
    """
    donnees = dechiffrer(ancien_mdp, nom, blob)
    return chiffrer(nouveau_mdp, nom, donnees, t=nouveau_t, m=nouveau_m, p=nouveau_p)
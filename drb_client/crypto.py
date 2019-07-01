import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from . import bn256

COORD_SIZE = 32
backend = default_backend()

def unmarshall_pubkey(pubkey):
    assert len(pubkey) == 4 * COORD_SIZE
    coords = tuple( int.from_bytes(pubkey[n*COORD_SIZE:(n+1) * COORD_SIZE], 'big') for n in range(4) )
    pk = bn256.curve_twist(
        bn256.gfp_2(coords[0], coords[1]),
        bn256.gfp_2(coords[2], coords[3]),
        bn256.gfp_2(0,1))
    assert pk.is_on_curve()
    return pk

def marshall_pubkey(pubkey):
    pubkey.force_affine()
    P = bn256.g2_marshall(pubkey)
    return b''.join(coord.to_bytes() for coord in P)

def keygen():
    priv, pub = bn256.g2_random()
    return priv, pub

def key_from_point(point):
    dh_bin = marshall_pubkey(point)
    hkdf = HKDF(algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=None,
                backend=backend)
    shared_key = hkdf.derive(dh_bin)
    return shared_key

def ecies_encrypt(recipient_pubkey, msg):
    priv, pub = keygen()
    dh_point = recipient_pubkey.scalar_mul(priv)
    shared_key = key_from_point(dh_point)
    nonce = os.urandom(12)
    aesgcm = AESGCM(shared_key)
    ct = aesgcm.encrypt(nonce, msg, None)
    return {
        'ephemeral': {
            'gid': 22,
            'point': marshall_pubkey(pub).hex(),
        },
        'nonce': nonce.hex(),
        'ciphertext': ct.hex(),
    }

def ecies_decrypt(privkey, box):
    assert box['ephemeral']['gid'] == 22 # G2
    eph_point = unmarshall_pubkey(bytes.fromhex(box['ephemeral']['point']))
    dh_point = eph_point.scalar_mul(privkey)
    shared_key = key_from_point(dh_point)
    aesgcm = AESGCM(shared_key)
    pt = aesgcm.decrypt(bytes.fromhex(box['nonce']),
                        bytes.fromhex(box['ciphertext']),
                        None)
    return pt


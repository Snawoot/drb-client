import os
import logging
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from . import bn256

COORD_SIZE = 32
AES_GCM_NONCE_SIZE = 12
AES_GCM_KEY_SIZE = 32
G2_GID = 22
G2_COORDS = 4
backend = default_backend()

def unmarshall_pubkey(pubkey):
    if not len(pubkey) == G2_COORDS * COORD_SIZE:
        raise ValueError("G2: bad binary string length.")
    coords = tuple( int.from_bytes(pubkey[n*COORD_SIZE:(n+1) * COORD_SIZE], 'big') for n in range(4) )
    pk = bn256.g2_unmarshall(*coords)
    if not pk.is_on_curve():
        raise ValueError("G2: point is not on curve!")
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
                length=AES_GCM_KEY_SIZE,
                salt=None,
                info=None,
                backend=backend)
    shared_key = hkdf.derive(dh_bin)
    return shared_key

def ecies_encrypt(recipient_pubkey, msg):
    priv, pub = keygen()
    dh_point = recipient_pubkey.scalar_mul(priv)
    shared_key = key_from_point(dh_point)
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(shared_key)
    ct = aesgcm.encrypt(nonce, msg, None)
    return {
        'ephemeral': {
            'gid': G2_GID,
            'point': marshall_pubkey(pub).hex(),
        },
        'nonce': nonce.hex(),
        'ciphertext': ct.hex(),
    }

def ecies_decrypt(privkey, box):
    if not box['ephemeral']['gid'] == G2_GID:
        raise ValueError("Unsupported curve point!")
    eph_point = unmarshall_pubkey(bytes.fromhex(box['ephemeral']['point']))
    dh_point = eph_point.scalar_mul(privkey)
    shared_key = key_from_point(dh_point)
    aesgcm = AESGCM(shared_key)
    pt = aesgcm.decrypt(bytes.fromhex(box['nonce']),
                        bytes.fromhex(box['ciphertext']),
                        None)
    return pt

class BaseEntropyMixer(ABC):
    @abstractmethod
    def mix(portions):
        """ Accepts iterable with `bytes` strings to mix """

class StatefulHKDFEntropyMixer(BaseEntropyMixer):
    def __init__(self, initial_salt=None):
        self._output_size = 32
        if not initial_salt:
            self._current_salt = os.urandom(self._output_size)
        else:
            self._current_salt = initial_salt
        self._logger = logging.getLogger(self.__class__.__name__)

    def mix(self, data):
        data = b''.join(data)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self._output_size,
            salt=self._current_salt,
            info=b'nextsalt',
            backend=backend)
        next_salt = hkdf.derive(data)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self._output_size,
            salt=self._current_salt,
            info=b'main_output',
            backend=backend)
        main_output = hkdf.derive(data)
        self._current_salt = next_salt
        self._logger.debug("KDF OUTPUT: salt=%s main=%s",
                           next_salt.hex(),
                           main_output.hex())
        return main_output

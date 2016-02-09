# Homework 1 (CS5830) 
# Trying to implement a length preserving Encryption function.
# 

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import base64
import binascii

def xor(a,b):
    """
    xors two raw byte streams.
    """
    assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
    return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

class MyFeistel:
    def __init__(self, key, num_rounds, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Key must be 16 url-safe base64-encoded bytes. Got: {} ({})".format(key, len(key))
            )
        self._num_rounds = num_rounds
        self._encryption_key = key[16:]
        self._backend = backend
        self._round_keys = [self._encryption_key \
                            for _ in xrange(self._num_rounds)]
        for i  in xrange(self._num_rounds):
            if i==0: continue
            self._round_keys[i] = self.SHA256hash(self._round_keys[i-1])

    def _SHA256hash(self, data):
        h = hashes.Hash(hashes.SHA256(), self._backend)
        h.update(data)
        return h.finalize()

    def encrypt(self, data):  # TODO: add tweak
        assert len(data)%2 == 0, "Supports only balanced feistel at "\
            "this moment. So provide even length messages."

        # TODO - Fill in
        pass

    def decrypt(self, ctx):
        assert len(data)%2 == 0, "Supports only balanced feistel at "\
            "this moment. So provide even length ciphertext."
        #TODO - Fill in
        pass

    def _prf(self, key, data):
        """Set up secure round function F
        """
        # TODO - set up round funciton using AES 
        pass

    def _feistel_round_enc(self, data):
        """This function implements one round of Fiestel encryption block.
        """
        # TODO - Implement this function 
        pass

    def _feistel_round_dec(self, data):
        """This function implements one round of Fiestel decryption block.
        """
        # TODO - Implement this function 
        pass

class LengthPreservingCipher(object):
    def __init__(self, key, length=40):
        self._length = 40
        #TODO 

    def encrypt(self, data):
        # TODO
        pass

    def decrypt(self, data):
        # TODO
        pass

    # TODO - add other functions if required

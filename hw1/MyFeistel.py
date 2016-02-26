# Homework 1 (CS5830) 
# Trying to implement a length preserving Encryption function.
# 

from cryptography.hazmat.primitives import hashes, padding, ciphers, hmac
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
        if len(key) != 16:
            raise ValueError(
                "Key must be 16 url-safe base64-encoded bytes. Got: {} ({})".format(key, len(key))
            )
        self._num_rounds = num_rounds
        self._encryption_key = key
        self._backend = backend
        self._round_keys = [self._encryption_key \
                            for _ in xrange(self._num_rounds)]
        for i  in xrange(self._num_rounds):
            if i==0: continue
            self._round_keys[i] = self.SHA256hmac('', self._round_keys[i-1])

    def SHA256hmac(self, key, data):
        # h = hashes.Hash(hashes.SHA256(), self._backend)
        h = hmac.HMAC(key, hashes.SHA256(), backend=self._backend)
        h.update(data)
        return h.finalize()

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):  # TODO: add tweak
        return self._feistel_round_enc(data)

    def decrypt(self, ctx):
        return self._feistel_round_dec(ctx)

    def _pad_string(self, data):
        """pad data if required, returns both a boolean (whether it is padded), 
        and the padded string
        """
        h_data = data.encode('hex')
        n = len(data)
        if n%2 == 0:
            return False, data
        l,r = h_data[:n], h_data[n:]
        l = '0' + l
        r = '0' + r
        return True, (l+r).decode('hex')

    def _prf(self, key, data):
        length_padded_data = "%d%s" % (len(data), data)
        block_size = ciphers.algorithms.AES.block_size
        padder = padding.PKCS7(block_size).padder()
        iv = '0'*(block_size/8) # Static IV, because we don't want it to be random.

        padded_data = padder.update(length_padded_data) + padder.finalize()
        encryptor = ciphers.Cipher(ciphers.algorithms.AES(self._encryption_key),
                                   ciphers.modes.CBC(iv),
                                   self._backend).encryptor()
        
        # Last block of the ciphertext is the CBC-MAC of the
        # message. Now we shall use this as a key to create a PRF
        new_k = (encryptor.update(padded_data) +
                 encryptor.finalize())[-(block_size/8):]
        ret = ''
        dummy_data = iv  # same as 0^16
        while len(ret)<len(data):
            encryptor = ciphers.Cipher(ciphers.algorithms.AES(new_k),
                                       ciphers.modes.ECB(),
                                       self._backend).encryptor()
            # Comput E(k, iv), E(k, E(k, iv)) etc.
            # I don't think we have to prepend with 0, 1, 2 etc, but need to check.
            dummy_data = (encryptor.update(dummy_data) + encryptor.finalize())
            ret += dummy_data
        return ret[:len(data)]

    def _prf_hmac(self, key, data):
        out = self.SHA256hmac(key, data) # TODO: SecCheck
        while len(out)<len(data):
            out += self.SHA256hmac(key, out)
        return out[:len(data)]

    def _clear_most_significant_four_bits(self, s):
        """
        Clear the first four bits of s and set it to 0.
        e.g, 0xa1 --> 0x01, etc.
        """
        assert len(s) == 1, "You called _clear_most_significant_four_bits function, "\
            "and I only work with 1 byte"
        return ('0' + s.encode('hex')[1]).decode('hex')

    def _feistel_round_enc(self, data):
        is_padded, padded_data = self._pad_string(data)  # Odd length message, we have to pad, and remove it later
        n = len(padded_data)
        L, R = padded_data[:n/2], padded_data[n/2:]
        for k in self._round_keys:
            L, R = R, xor(L, self._prf(k, R))
            if is_padded: # Why only R, because first four bits of L is already cleard.  
                R = self._clear_most_significant_four_bits(R[0])+R[1:]
        if is_padded: # As we padded the data, we have to remove the padding
            return (L.encode('hex')[1:] + R.encode('hex')[1:]).decode('hex')
        else:
            return L + R

    def _feistel_round_dec(self, data):
        is_padded, padded_data = self._pad_string(data)  # Odd length message, we have to pad, and remove it later
        n = len(padded_data)
        L, R = padded_data[:n/2], padded_data[n/2:]
        for k in self._round_keys[::-1]:
            L, R = xor(R, self._prf(k, L)), L
            if is_padded: # Why only R, because first four bits of L is already cleard.  
                L = self._clear_most_significant_four_bits(L[0])+L[1:]
        if is_padded: # As we padded the data, we have to remove the padding
            return (L.encode('hex')[1:] + R.encode('hex')[1:]).decode('hex')
        else:
            return L + R

        
class LengthPreservingCipher(MyFeistel):
    def __init__(self, key, length=5):
        self._length = 5
        self._round = 10
        self._cipher = MyFeistel(key, 10)

    def _apply_feistel(self, data, ischop):
        """
        @data: data to encrypt. Expects that the data is already padded.
        @ischop: is the length of the padding for both L and R
        """
        ctx = data
        n = len(ctx)
        for i_round in xrange(self._round):
            ctx = self._cipher.encrypt(ctx).encode('hex')
            L, R = ctx[:n], ctx[n:]  # Note there is a padding of the data,
                                     # which we may want to remove or replace
                                     # with zeros.
            if ischop:
                if i_round==self._round-1: # Last round
                    L, R  = L[1:], R[1:]
                else:
                    L, R = '0' + L[1:], '0' + R[1:] 
            ctx = (L+R).decode('hex')
        return ctx  # Returns unpadded cipher text after applying the Feistel
                    # rounds
    
    def encrypt(self, data):
        assert len(data) == self._length, "The length of the data ({}) is incorrect. Should be {}."\
                                .format(len(data), self._length)
        return self._cipher.encrypt(data)
        
    def decrypt(self, ctx):
        assert len(ctx) == self._length, "The length of the data ({}) is incorrect. Should be {}."\
                                .format(len(ctx), self._length)
        return self._cipher.decrypt(ctx)



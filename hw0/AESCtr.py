from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import binascii
import os
import struct


def xor(a,b):
    """
    xors two raw byte streams.
    """
    assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
    return ''.join(chr(ord(ai)^ord(bi)) for ai,bi in zip(a,b))

class AESCtr:
  def __init__(self, key, backend=None):
    if backend is None:
      backend = default_backend()

      key = base64.urlsafe_b64decode(key)
      if len(key) != 16:
        raise ValueError("AES key must be 16 btyes long and url-safe base64-encoded."  
              "Got: {} ({})".format(key, len(key)))
      self._encryption_key = key
      self._backend = backend
      self._block_size_bytes = algorithms.AES.block_size / 8    # in bytes
      self._nonce_size = self._block_size_bytes / 2             # in bytes

  def _nonced_counters(self, nonce, numblocks):
    """Returns the nonced 16 byte counter required for ctr mode"""
    for ctr in xrange(numblocks):
      yield nonce + struct.pack('>Q', ctr)

  def _encrypt_one_block(self, data):
    encryptor = Cipher(algorithms.AES(self._encryption_key),modes.ECB(),self._backend).encryptor()
    return encryptor.update(data) + encryptor.finalize()

  def _encryptor_engine(self, nonce, data):
    num_blocks = (len(data) + self._block_size_bytes-1)/(self._block_size_bytes) # number of blocks
    ctx = []
    for ctr, i in zip(self._nonced_counters(nonce, num_blocks), 
                      xrange(0, num_blocks)):
      start = i*self._block_size_bytes
      end = start + self._block_size_bytes
      block_data = data[start:end]
      enc_ctr = self._encrypt_one_block(ctr)
      if len(block_data) < self._block_size_bytes:
        enc_ctr= enc_ctr[:len(block_data)]
      ctx.append(xor(enc_ctr, block_data))
    return ''.join(ctx)

  def encrypt(self, data):
    """ This function takes a byte stream @data and outputs the  ciphertext """
    if not isinstance(data, bytes):
      raise TypeError("data must be bytes.")

    nonce = os.urandom(self._nonce_size); # a.k.a nonce
    return nonce+self._encryptor_engine(nonce, data)

  def decrypt(self, ctx):
    if not isinstance(ctx, bytes):
      raise TypeError("data must be bytes.")

    nonce, data = ctx[:self._nonce_size], ctx[self._nonce_size:]
    txt = self._encryptor_engine(nonce, data)
    return txt
  


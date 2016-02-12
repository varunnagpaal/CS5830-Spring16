
#!/usr/bin/python 

from AESCtr import AESCtr
import pytest
import base64
import os


def test_basic():
  """
  Test: dec(enc(txt)) == txt, and
  Test: len(ctx) = len(txt) + 8 (8 is for the nonce/IV)
  (Note, if you use padding disable the length check test
  """  
  key = base64.urlsafe_b64encode(os.urandom(16))
  aes = AESCtr(key)
  testtxt = ['a', 'ab', '', 'A great Secret message'*12, '0'*10000]
  for txt in testtxt:
    ctx = aes.encrypt(txt)
    dtxt = aes.decrypt(ctx)
    assert len(ctx) - len(txt) == aes._nonce_size  # Disable this test if you are using pading
    assert dtxt==txt, "The decrypted text is not the same as the original text"


def test_ctxdist1():
  """
  Test 1: All the blocks in the cipher text should be unique (with very high probability). 
  Test 2: Encrypting the same message 1000 times should return 1000 different ciphertexts.
  """

  key = base64.urlsafe_b64encode(os.urandom(16))
  aes = AESCtr(key)
  txt = 'a'*2000
  # remove the IV, otherwise the ctx will be trivially different.
  n = 1000
  ctx = aes.encrypt(txt)[8:]
  num_unique_blocks = len(set(ctx[i:i+aes._block_size_bytes] \
                              for i in xrange(0, len(ctx), aes._block_size_bytes)))

  num_blocks = len(txt[::aes._block_size_bytes])
  assert num_blocks == num_unique_blocks, "Repeating ciphertext blocks"
  
  # There should not be any repeat. If they are not same, then most
  # probably the ciphertexts are random
  assert len(list(set(aes.encrypt(txt)[8:] for i in xrange(n)))) == n, "Repeating whole ciphertext!"

  
def test_ctxdist2():
  """
  Test 1: Cipher text of different messages are different
  """

  n = 1000
  key = base64.urlsafe_b64encode(os.urandom(16))
  aes = AESCtr(key)
  next_ctx = lambda : aes.encrypt(os.urandom(1000))[:8]
  assert len(list(set(next_ctx() for i in xrange(n)))) == n, "Repeating whole ciphertext for differet messages!"
  
def test_keyvalid():
  """
  Wrong key should output junk.
  """
  n = 1000
  key = base64.urlsafe_b64encode(os.urandom(16))
  aes = AESCtr(key)
  txt = os.urandom(1000)
  ctx = aes.encrypt(txt)
  def next_ctx():
    key = base64.urlsafe_b64encode(os.urandom(16))
    aes = AESCtr(key)
    return aes.decrypt(ctx)
  output_ptxt = set(next_ctx() for i in xrange(n))
  assert txt not in output_ptxt, "Decryption output same for different key!"
  assert len(output_ptxt) == n, "Repeating whole ciphertext for differet keys!"


from LengthCipher import MyFeistel, LengthPreservingCipher
import pytest
import base64
import os

class TestMyFeistel:
    def test_MyFeistel(self):
        key = base64.urlsafe_b64encode(os.urandom(16))
        # TODO

class TestLengthPreservingCipher:
    def test_LengthPreservingCipher(self):
        # TODO 
        pass

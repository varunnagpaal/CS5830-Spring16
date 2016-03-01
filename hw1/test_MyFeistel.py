from MyFeistel import MyFeistel, LengthPreservingCipher
import pytest
import base64
import os
from collections import defaultdict
import math

class TestMyFeistel(object):
    def setup(self):
        key = base64.urlsafe_b64encode('1234567890abcdef')        
        self._feistel = MyFeistel(key, num_rounds=10)
        self._feistel1 = MyFeistel(key, num_rounds=1)
        self._feistel2 = MyFeistel(key, num_rounds=2)
        self._feistel10 = MyFeistel(key,num_rounds=10)

    def test_basic(self):
        txt = b'A great Secret message'*12  # To make it larger than 128-bit
        self.setup()
        # round 1
        ctx = self._feistel1.encrypt(txt)
        dtxt = self._feistel1.decrypt(ctx)
        assert dtxt==txt, "Failed 1-round Feistel test"
        
        # round 2
        ctx = self._feistel2.encrypt(txt)
        dtxt = self._feistel2.decrypt(ctx)
        assert dtxt==txt, "Failed 2-round test"

        # round 10
        ctx = self._feistel10.encrypt(txt)
        dtxt = self._feistel10.decrypt(ctx)
        assert dtxt==txt, "Failed 10-round test"

    def test_round1_LR_msg(self):
        txt = 'ThemessageisSecret'
        ctx = self._feistel1.encrypt(txt)
        n = len(ctx)
        assert ctx[:n/2] == txt[n/2:]

    def test_even_length_messages(self):
        self.setup()
        for i in range(2, 300, 2):
            txt = 'a'*i
            try:
                ctx = self._feistel.encrypt(txt)
            except AssertionError:
                ctx = ''

            try:
                dtxt = self._feistel.decrypt(ctx) if len(ctx)>0 else ''
            except AssertionError:
                dtxt = ''

            assert dtxt==txt
            assert len(ctx) == len(txt)

    def test_odd_length(self):
        """
        Test: dec(enc(txt)) == txt, and
        Test: len(ctx) = len(txt) + 8 (8 is for the nonce/IV)
        (Note, if you use padding disable the length check test
        """  
        self.setup()
        for i in range(1, 300, 2):
            txt = 'a'*i
            try:
                ctx = self._feistel.encrypt(txt)
            except AssertionError:
                ctx = ''

            try:
                dtxt = self._feistel.decrypt(ctx) if len(ctx)>0 else ''
            except AssertionError:
                dtxt = ''

            assert dtxt==txt
            assert len(ctx) == len(txt)

    def test_ctxdist1(self):
        """Test the frequency of bytes in the cipher text for the same
        message and different keys.
        """
        self.setup()
        txt = "Thequickbrownfoxjumpsoverthelazydog"
        cnt_dict = defaultdict(int)
        def _count_dict(s):
            for c in s:
                cnt_dict[c] += 1

        exp_cnt = 10000
        for i in xrange(exp_cnt):
            key = base64.urlsafe_b64encode(os.urandom(16))
            ctx = MyFeistel(key, 10).encrypt(txt)
            _count_dict(ctx)
        t = sum(cnt_dict.values())
        n = len(cnt_dict)
        assert t == exp_cnt * len(txt)
        expected_mean = t/256
        expected_sd = math.sqrt(t * 255)/256

        # Ideally the right hand side of the follwoing equations
        # shoudl be (mean +- 2 * sigma), but it is too close, and the
        # test is failing many times. That's why I am making it (4 *
        # sigma).
        # I should rather use standard statistical testing 
        # framework for this.
        assert max(cnt_dict.values()) < expected_mean + 4*expected_sd
        assert max(cnt_dict.values()) > expected_mean - 4*expected_sd


    def test_ctxdist2(self):
        """
        Test 1: Cipher text of different messages are different
        """
        self.setup()
        n = 1000
        next_ctx = lambda : self._feistel.encrypt(os.urandom(10))
        assert len(set(next_ctx() for i in xrange(n))) == n, "Repeating whole ciphertext for differet messages!"
        
    def test_keyvalid(self):
        """
        Wrong key should output junk.
        """
        n = 1000
        txt = os.urandom(100)
        self.setup()
        ctx = self._feistel.encrypt(txt)
        def next_ctx():
            key = base64.urlsafe_b64encode(os.urandom(16))
            feistel = MyFeistel(key, 10)
            return feistel.decrypt(ctx)
        
        output_ptxt = set(next_ctx() for i in xrange(n))
        assert txt not in output_ptxt, "Decryption output same for different key!"
        assert len(output_ptxt) == n, "Repeating whole ciphertext for differet keys!"

    def test_part_of_the_message_is_not_revealed(self):
        """
        Tests whether part of the message is revealed or not. 
        """
        self.setup()
        for i in xrange(1, 20):
            n = i*10
            txt = os.urandom(n)
            ctx = self._feistel10.encrypt(txt)
            assert ctx.find(txt[n/2:]) == -1, "{} <--> {}".format(repr(ctx), repr(txt))
            assert ctx.find(txt[:n/2]) == -1, "{} <--> {}".format(repr(ctx), repr(txt))
        
class TestLengthPreservingCipher:
    def setup(self):
        key = base64.urlsafe_b64encode('1234567890abcdef')        
        self._lpc5 = LengthPreservingCipher(key, 5)

    def test_basic(self):
        self.setup()
        txt = b'abcde'
        ctx = self._lpc5.encrypt(txt)
        ttxt = self._lpc5.decrypt(ctx)
        assert ttxt == txt

    def test_random_msg(self):
        self.setup()
        for i in xrange(101):
            txt = os.urandom(5)
            ctx = self._lpc5.encrypt(txt)
            ttxt = self._lpc5.decrypt(ctx)
            assert txt == ttxt, "Input and out messages do not match. {:02X} != {!02X}".format(txt, ttxt)

    def test_wrong_length_encrpyt(self):
        self.setup()
        with pytest.raises(AssertionError) as e:
            self._lpc5.encrypt('a')
        with pytest.raises(AssertionError) as e:
            self._lpc5.encrypt('a'*6)

    def test_wrong_length_decrypt(self):
        self.setup()
        msg = 'a'
        with pytest.raises(AssertionError) as e:
            self._lpc5.decrypt('a')
        with pytest.raises(AssertionError) as e:
            self._lpc5.decrypt('a'*6)

    def test_length_of_cipher(self):
        self.setup()
        txt = b'abcde'
        ctx = self._lpc5.encrypt(txt)
        assert len(ctx) == len(txt)

            

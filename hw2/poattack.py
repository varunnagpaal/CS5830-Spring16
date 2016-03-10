from paddingoracle import PaddingOracle, xor, PaddingOracleServer
from cryptography.hazmat.primitives import padding, ciphers
import os, random
from urllib2 import urlopen
import json
import base64

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]

        
def po_attack_2blocks(po, ctx):
    """Given two block message can recover the first block of the message.
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))
    msg = ''
    for i in range(1, po.block_length+1):
        # print "Trying for block: {}".format(po.block_length - i)
        found = False
        for z in xrange(0x00, 0xff+1):
            guess_msg_xor_padding = xor(chr(z) + msg,  chr(i)*i)
            nctx = c0[:-i] + xor(c0[-i:], guess_msg_xor_padding) + c1
            if po.decrypt(nctx):
                # test if it is the last byte and the padding is indeed correct.
                if i==1:  # the last byte of the message
                    nctx = c0[:-2] + chr(ord(c0[-2]) ^ 1) + chr(ord(c0[-1]) ^ z ^ i) + c1
                    if not po.decrypt(nctx):
                        # print ">>>> Got a misencryption.", nctx.encode('hex')
                        continue
                msg = chr(z) + msg
                found = True
                break
        assert found, "Ohh damn, could not find: <{}> @ i={}".format(msg.encode('hex'), i)
    return msg

def po_attack(po, ctx):
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    print "Numblocks: {}".format(nblocks)
    msg = ''.join(po_attack_2blocks(po, ctx_blocks[i]+ctx_blocks[i+1])
                  for i in xrange(nblocks-1))
    unpadder = padding.PKCS7(ciphers.algorithms.AES.block_size).unpadder()
    return unpadder.update(msg) + unpadder.finalize()



################################################################################
############################## Testing Framework ###############################
################################################################################
def test_po_attack_2blocks():
    for i in xrange(16):
        po = PaddingOracle(msg_len=i)
        ctx = po.ciphertext()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)

def test_po_attack():
    import random
    for i in xrange(100):
        l = random.randint(1, (i+1)*10)
        po = PaddingOracle(msg_len=l)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        #print msg
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)
        print "{}. Length: {} passed".format(i, l)

test_po_attack_2blocks()
test_po_attack()

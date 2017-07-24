#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
'''
# ϶ 𝕩 𝕠 я н ᴧ 𝕤 н ϶ 𝕩 𝕠
#                   я
#    ┏┓┏┓┏━━┓┏━┓    н
#    ┗╋╋┛┃┏┓┃┃┏┛    ᴧ
#    ┏╋╋┓┃┗┛┃┃┃     𝕤     
#    ┗┛┗┛┗━━┛┗┛     н    (𝕓𝕚𝕥𝕞𝕖𝕤𝕤𝕒𝕘𝕖) < BM-NBTqJ12baBSKxqdnQedyhFVUWborkho3 >
#                   𝕤                   (𝕖𝕞𝕒𝕚𝕝) < xor@danwin1210.me >
#     ϶𝕩𝕠я нᴧ𝕤н     ᴧ
#      𝕔𝕠𝕞𝕤𝕖𝕔             н
#                   я                    Ⓒ 2017, 𝗘𝗫𝗢𝗥  𝗛𝗔𝗦𝗛  𝗖𝗢𝗠𝗦𝗘𝗖
# ϶ 𝕩 𝕠 я н ᴧ 𝕤 н ϶ 𝕩 𝕠 


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

chanerator v0


    ┏┓                      ┏┓
    ┃┃                     ┏┛┗┓
┏━━┓┃┗━┓┏━━┓┏━┓ ┏━━┓┏━┓┏━━┓┗┓┏┛┏━━┓┏━┓
┃┏━┛┃┏┓┃┃┏┓┃┃┏┓┓┃┃━┫┃┏┛┃┏┓┃ ┃┃ ┃┏┓┃┃┏┛
┃┗━┓┃┃┃┃┃┏┓┃┃┃┃┃┃┃━┫┃┃ ┃┏┓┃ ┃┗┓┃┗┛┃┃┃
┗━━┛┗┛┗┛┗┛┗┛┗┛┗┛┗━━┛┗┛ ┗┛┗┛ ┗━┛┗━━┛┗┛

contact / broadcast: (3X0R) < BM-NBTqJ12baBSKxqdnQedyhFVUWborkho3 >

The chanerator generates a bitmessage stream 1 chan address on the command line.

A bash alias to the script makes it useful for fast testing.

Modeled from Bitmessage VanityGen (by 'nimda') and a later version, 'bmgen.py.'
https://bitmessage.org/forum/index.php?topic=1727.0
https://gist.github.com/anonymous/43c7d9690e57558b10e59720b29dc2d6

Usage: $ python2 chanerator.py [passphrase]

Use is subject to license and indemnification of the author(s) from all claims.

LICENSE AGREEMENT:

By using this software you agree to hold the author harmless. This software is
provided with no warranty. It is not warranted to have fitness for any purpose.
User agrees that any usage is absolutely at user's own risk with no recourse.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
'''

import sys, os, base64, hashlib, time
from struct import Struct
from pyelliptic.openssl import OpenSSL
import ctypes
from binascii import hexlify
from collections import deque
from hashlib import sha256, sha512


pack_B = Struct('>B').pack
pack_BH = Struct('>BH').pack
pack_BI = Struct('>BI').pack
pack_BQ = Struct('>BQ').pack
def encodeVarint(integer):
    if not (0 <= integer < 18446744073709551616):
        raise ValueError('varint must be >= 0 and < 2**64')
    if integer < 253:
        return pack_B(integer)
    if integer < 65536:
        return pack_BH(253, integer)
    if integer < 4294967296:
        return pack_BI(254, integer)
    return pack_BQ(255, integer)

def encodeAddress(version, stream, ripe):
    if len(ripe) != 20:
        raise ValueError('ripe must be exactly 20 bytes')
    if 2 <= version < 4:
        if ripe[:2] == '\x00\x00':
            ripe = ripe[2:]
        elif ripe[:1] == '\x00':
            ripe = ripe[1:]
    elif version == 4:
        ripe = ripe.lstrip('\x00')
        if len(ripe) < 4:
            raise ValueError('ripe must not contain more than 16 leading NUL bytes')
    else:
        raise ValueError('address version %s not supported' % version)

    address_data = encodeVarint(version) + encodeVarint(stream) + ripe
    address_data += sha512(sha512(address_data).digest()).digest()[:4]

    return 'BM-'+ encodeBase58(address_data)

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def encodeBase58(data, alphabet=ALPHABET):
    if not data:
        return ''
    num = int(hexlify(data), 16)
    if not num:
        return alphabet[0]
    arr = deque()
    base = len(alphabet)
    while num:
        num, rem = divmod(num, base)
        arr.appendleft(alphabet[rem])
    return ''.join(arr)

def pointMult(secret):
    k = OpenSSL.EC_KEY_new_by_curve_name(OpenSSL.get_curve('secp256k1')) 
    priv_key = OpenSSL.BN_bin2bn(secret, 32, 0)
    group = OpenSSL.EC_KEY_get0_group(k)
    pub_key = OpenSSL.EC_POINT_new(group)

    OpenSSL.EC_POINT_mul(group, pub_key, priv_key, None, None, None)
    OpenSSL.EC_KEY_set_private_key(k, priv_key)
    OpenSSL.EC_KEY_set_public_key(k, pub_key)
    
    size = OpenSSL.i2o_ECPublicKey(k, 0)
    mb = ctypes.create_string_buffer(size)
    OpenSSL.i2o_ECPublicKey(k, ctypes.byref(ctypes.pointer(mb)))
    
    OpenSSL.EC_POINT_free(pub_key)
    OpenSSL.BN_free(priv_key)
    OpenSSL.EC_KEY_free(k)
    return mb.raw

found_one = False

def chanerate():
    global found_one
    passphrase = args[0]
    deterministicNonce = 0
    startTime = time.time()
    while found_one != True:
        
        deterministicNall = str(passphrase)
        address=""
        while found_one != True:
            
            signingKeyNonce = 0
            encryptionKeyNonce = 1
            numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix = 0
            deterministicPassphrase = deterministicNall
            while found_one != True:
                numberOfAddressesWeHadToMakeBeforeWeFoundOneWithTheCorrectRipePrefix += 1
                potentialPrivSigningKey = sha512(deterministicPassphrase + encodeVarint(signingKeyNonce)).digest()[:32]
                potentialPrivEncryptionKey = sha512(deterministicPassphrase + encodeVarint(encryptionKeyNonce)).digest()[:32]
                potentialPubSigningKey = pointMult(potentialPrivSigningKey)
                potentialPubEncryptionKey = pointMult(potentialPrivEncryptionKey)
                signingKeyNonce += 2
                encryptionKeyNonce += 2
                ripe = hashlib.new('ripemd160', sha512(potentialPubSigningKey + potentialPubEncryptionKey).digest()).digest()
                
                if ripe[:1] == '\x00':
                        break
                

            address = encodeAddress(4,1,ripe)

            privSigningKey = '\x80' + potentialPrivSigningKey
            checksum = sha256(sha256(privSigningKey).digest()).digest()[0:4]
            privSigningKeyWIF = encodeBase58(privSigningKey + checksum)

            privEncryptionKey = '\x80' + potentialPrivEncryptionKey
            checksum = sha256(sha256(privEncryptionKey).digest()).digest()[0:4]
            privEncryptionKeyWIF = encodeBase58(privEncryptionKey + checksum)

            deterministicNonce += 1
            if (address[:2] == "BM"):
                print "[" + address+ "]"
                print "label = [chan] " + str(deterministicPassphrase)
                print "enabled = true"
                print "decoy = false"
                print "chan = true"
                print "noncetrialsperbyte = 1000"
                print "payloadlengthextrabytes = 1000"
                print "privsigningkey = " + privSigningKeyWIF
                print "privencryptionkey = " + privEncryptionKeyWIF
                found_one = True
                
                break

        if (found_one == True):
            break

from optparse import OptionParser
usage = "usage: %prog [options] passphrase"
parser = OptionParser(usage=usage)

parser.add_option("-i", "--info",
                  action="store_true", dest="info", default=False,
                  help="Show license and author info.")
                  
parser.add_option("-l", "--logo",
                  action="store_true", dest="logo", default=False,
                  help="Show logo and contact info.")

(options, args) = parser.parse_args()

if options.info:
    print """
╋╋╋╋┏┓╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┏┓
╋╋╋╋┃┃╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┏┛┗┓
┏━━┓┃┗━┓┏━━┓┏━┓╋┏━━┓┏━┓┏━━┓┗┓┏┛┏━━┓┏━┓
┃┏━┛┃┏┓┃┃┏┓┃┃┏┓┓┃┃━┫┃┏┛┃┏┓┃╋┃┃╋┃┏┓┃┃┏┛
┃┗━┓┃┃┃┃┃┏┓┃┃┃┃┃┃┃━┫┃┃╋┃┏┓┃╋┃┗┓┃┗┛┃┃┃
┗━━┛┗┛┗┛┗┛┗┛┗┛┗┛┗━━┛┗┛╋┗┛┗┛╋┗━┛┗━━┛┗┛
    """
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    print ""
    print "chanerator v0"
    print ""
    print "Use subject to license."
    print ""
    print "contact / broadcast: (chanerator) < BM-NBTqJ12baBSKxqdnQedyhFVUWborkho3 >"
    print ""
    print "Generates a bitmessage stream 1 chan address on the command line."
    print ""
    print "A bash alias to the script makes it useful for fast testing."
    print ""
    print "Adapted from Bitmessage VanityGen (by 'nimda') and a later version, bmgen.py."
    print "https://bitmessage.org/forum/index.php?topic=1727.0"
    print "https://gist.github.com/anonymous/43c7d9690e57558b10e59720b29dc2d6"
    print ""
    print "Usage: $ python2 chanerator.py [passphrase]"
    print ""
    print "LICENSE AGREEMENT:"
    print "By using this software you agree to hold the author harmless. This software is"
    print "provided with no warranty. It is not warranted to have fitness for any purpose."
    print "User agrees that any usage is absolutely at user's own risk with no recourse."
    print ""
    print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    sys.exit()
    
if options.logo:
    shield = """

    ┏┓┏┓┏━━┓┏━┓
    ┗╋╋┛┃┏┓┃┃┏┛     (bitmessage) < BM-NBTqJ12baBSKxqdnQedyhFVUWborkho3 >
    ┏╋╋┓┃┗┛┃┃┃           (email) < xor@danwin1210.me >
    ┗┛┗┛┗━━┛┗┛         
                          (c)2017, EXOR HASH COMSEC.
                          
    """
    print shield
    sys.exit()

if len(args) == 0:
    parser.print_help()
    sys.exit()
    
chanerate()

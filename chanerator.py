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
import ctypes
import ctypes.util
from binascii import hexlify
from collections import deque
from hashlib import sha256, sha512


POINT_COMPRESSION_UNCOMPRESSED = 4

class _OpenSSL:
    '''Wrapper for OpenSSL using ctypes'''
    def __init__(self, library):
        if not library:
            library = 'libeay32.dll' if sys.platform == 'win32' else 'crypto'
            library = ctypes.util.find_library(library)
        self._lib = ctypes.CDLL(library)

        self._wrap('BN_bin2bn', ctypes.c_void_p, [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p])
        self._wrap('BN_clear_free', None, [ctypes.c_void_p])
        self._wrap('BN_new', ctypes.c_void_p, [])

        self._wrap('BN_CTX_free', None, [ctypes.c_void_p])
        self._wrap('BN_CTX_new', ctypes.c_void_p, [])

        self._wrap('EC_GROUP_clear_free', None, [ctypes.c_void_p])
        self._wrap('EC_GROUP_new_by_curve_name', ctypes.c_void_p, [ctypes.c_int])

        self._wrap('EC_POINT_clear_free', None, [ctypes.c_void_p])
        self._wrap('EC_POINT_new', ctypes.c_void_p, [ctypes.c_void_p])
        self._wrap('EC_POINT_point2oct', ctypes.c_size_t, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.c_void_p])
        self._wrap('EC_POINTs_mul', ctypes.c_int, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p])

        self._wrap('OBJ_sn2nid', ctypes.c_int, [ctypes.c_char_p])

        NID_secp256k1 = self.OBJ_sn2nid('secp256k1')
        if not NID_secp256k1:
            raise Exception('OpenSSL library missing NID_secp256k1')

        group = self.EC_GROUP_new_by_curve_name(NID_secp256k1)
        if not group:
            raise Exception('OpenSSL library missing elliptic curve secp256k1')
        self.group = group

        self.bn_ctx = self.BN_CTX_new()
        self.bn_private_key = self.BN_new()
        self.point_public_key = self.EC_POINT_new(group)
        self.buf = ctypes.create_string_buffer(65)

    def __del__(self):
        if getattr(self, 'point_public_key', 0):
            self.EC_POINT_clear_free(self.point_public_key)
        if getattr(self, 'bn_private_key', 0):
            self.BN_clear_free(self.bn_private_key)
        if getattr(self, 'bn_ctx', 0):
            self.BN_CTX_free(self.bn_ctx)
        if getattr(self, 'group', 0):
            self.EC_GROUP_clear_free(self.group)

    def _wrap(self, name, restype=None, argtypes=[]):
        if not hasattr(self._lib, name):
            raise Exception('OpenSSL library missing %s function' % name)
        f = getattr(self._lib, name)
        f.restype = restype
        f.argtypes = argtypes
        setattr(self, name, f)
    
    def get_public_key(self, raw_private_key):
        bn_private_key = self.bn_private_key
        bn_ctx = self.bn_ctx
        point_public_key = self.point_public_key
        group = self.group
        buf = self.buf
        self.BN_bin2bn(raw_private_key, 32, bn_private_key)
        self.EC_POINTs_mul(group, point_public_key, bn_private_key, 0, None, None, bn_ctx)
        self.EC_POINT_point2oct(group, point_public_key, POINT_COMPRESSION_UNCOMPRESSED, buf, len(buf), bn_ctx)
        return buf.raw

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
                potentialPubSigningKey = OpenSSL.get_public_key(potentialPrivSigningKey)
                potentialPubEncryptionKey = OpenSSL.get_public_key(potentialPrivEncryptionKey)
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

parser.add_option("--openssl", dest="library",
                  help="Path of OpenSSL library to use")

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
    
OpenSSL = _OpenSSL(options.library)
chanerate()

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
from struct import *
from pyelliptic.openssl import OpenSSL
import ctypes
from pyelliptic import arithmetic
from binascii import hexlify


def encodeVarint(integer):
    if integer < 0:
        print 'varint cannot be < 0'
        raise SystemExit
    if integer < 253:
        return pack('>B',integer)
    if integer >= 253 and integer < 65536:
        return pack('>B',253) + pack('>H',integer)
    if integer >= 65536 and integer < 4294967296:
        return pack('>B',254) + pack('>I',integer)
    if integer >= 4294967296 and integer < 18446744073709551616:
        return pack('>B',255) + pack('>Q',integer)
    if integer >= 18446744073709551616:
        print 'varint cannot be >= 18446744073709551616'
        raise SystemExit
    
def encodeAddress(version,stream,ripe):
    if version >= 2 and version < 4:
        if len(ripe) != 20:
            raise Exception("Programming error in encodeAddress: The length of a given ripe hash was not 20.")
        if ripe[:2] == '\x00\x00':
            ripe = ripe[2:]
        elif ripe[:1] == '\x00':
            ripe = ripe[1:]
    elif version == 4:
        if len(ripe) != 20:
            raise Exception("Programming error in encodeAddress: The length of a given ripe hash was not 20.")
        ripe = ripe.lstrip('\x00')

    verVar = encodeVarint(version)
    strVar = encodeVarint(stream)
    storedBinaryData = encodeVarint(version) + encodeVarint(stream) + ripe
    

    sha = hashlib.new('sha512')
    sha.update(storedBinaryData)
    currentHash = sha.digest()
    sha = hashlib.new('sha512')
    sha.update(currentHash)
    checksum = sha.digest()[0:4]

    asInt = int(hexlify(storedBinaryData) + hexlify(checksum),16)
    return 'BM-'+ encodeBase58(asInt)

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def encodeBase58(num, alphabet=ALPHABET):
   
    if (num == 0):
        return alphabet[0]
    arr = []
    base = len(alphabet)
    while num:
        rem = num % base
        num = num // base
        arr.append(alphabet[rem])
    arr.reverse()
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
                potentialPrivSigningKey = hashlib.sha512(deterministicPassphrase + encodeVarint(signingKeyNonce)).digest()[:32]
                potentialPrivEncryptionKey = hashlib.sha512(deterministicPassphrase + encodeVarint(encryptionKeyNonce)).digest()[:32]
                potentialPubSigningKey = pointMult(potentialPrivSigningKey)
                potentialPubEncryptionKey = pointMult(potentialPrivEncryptionKey)
                signingKeyNonce += 2
                encryptionKeyNonce += 2
                ripe = hashlib.new('ripemd160')
                sha = hashlib.new('sha512')
                sha.update(potentialPubSigningKey+potentialPubEncryptionKey)
                ripe.update(sha.digest())
                
                if ripe.digest()[:1] == '\x00':
                        break
                

            address = encodeAddress(4,1,ripe.digest())

            privSigningKey = '\x80' + potentialPrivSigningKey
            checksum = hashlib.sha256(hashlib.sha256(
                privSigningKey).digest()).digest()[0:4]
            privSigningKeyWIF = arithmetic.changebase(
                privSigningKey + checksum, 256, 58)

            privEncryptionKey = '\x80' + potentialPrivEncryptionKey
            checksum = hashlib.sha256(hashlib.sha256(
                privEncryptionKey).digest()).digest()[0:4]
            privEncryptionKeyWIF = arithmetic.changebase(
                privEncryptionKey + checksum, 256, 58)

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

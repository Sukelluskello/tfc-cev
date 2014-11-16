#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import binascii
import csv
import getopt
import hashlib
import imp
import math
import os
import random
import re
import readline
import serial
import string
import subprocess
import sys
import time
import zlib
from time import sleep
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from ctypes import (cdll, c_char_p, c_int, c_uint64, create_string_buffer)
from ctypes import (cdll, Structure, POINTER, pointer, c_char_p, c_int, c_uint32, create_string_buffer)

try:
    import Crypto.Random.random
    secure_random = Crypto.Random.random.getrandbits
except ImportError:
    import OpenSSL
    print 'WARNING Failed to import Crypto.Random, trying OpenSSL instead.'
    secure_random = lambda x: long(hexlify(OpenSSL.rand.bytes(x>>3)), 16)



######################################################################
#                              LICENCES                              #
######################################################################

# TFC-CEV
"""
This software is part of the TFC application, which is free software:
You can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. For a copy of the GNU General Public License, see
<http://www.gnu.org/licenses/>.

TFC-CEV (Cascading Encryption Version)
Tx.py
"""

version = '0.4.11 beta'

# Licences of encryption libraries

# Keccak
"""
Algorithm Name: Keccak
Authors: Guido Bertoni, Joan Daemen, Michael Peeters and Gilles Van Assche
Implementation by Renaud Bauvin, STMicroelectronics

This code, originally by Renaud Bauvin, is hereby put in the public domain.
It is given as is, without any guarantee.

For more information, feedback or questions, please refer to our website:
http://keccak.noekeon.org/
"""

# Salsa20
"""
This file is part of Python Salsa20
a Python bridge to the libsodium C [X]Salsa20 library
Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase
Python module and ctypes bindings
"""

# Twofish
"""
This file is part of Python Twofish a Python bridge to the C Twofish library by Niels Ferguson
Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase
Python module and ctypes bindings
"""

# AEC- GCM
"""
#  Cipher/AES.py : AES
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

PyCrypto licence (https://raw.githubusercontent.com/dlitz/pycrypto/master/COPYRIGHT)
To the best of our knowledge, with the exceptions noted below or
within the files themselves, the files that constitute PyCrypto are in
the public domain. Most are distributed with the following notice:
The contents of this file are dedicated to the public domain. To
the extent that dedication to the public domain is not available,
everyone is granted a worldwide, perpetual, royalty-free,
non-exclusive license to exercise all rights associated with the
contents of this file for any purpose whatsoever.

No rights are reserved.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

# Diffie-Hellman Key Exchange
"""
PyDHE - Diffie-Hellman Key Exchange in Python
Copyright (C) 2013 by Mark Loiseau

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


For more information:
http://blog.markloiseau.com/2013/01/diffie-hellman-tutorial-in-python/
"""



######################################################################
#                            CONFIGURATION                           #
######################################################################

os.chdir(sys.path[0])

PkgSize         = 144
maxSleepTime    = 13
kfOWIterations  = 3
lMsgSleep       = 0.2
emergencyExit   = False
randomSleep     = False
debugging       = False
localTesting    = True

if not localTesting:
    port        = serial.Serial('/dev/ttyAMA0', baudrate=9600, timeout=0.1)



######################################################################
#                          KECCAK STREAM CIPHER                      #
######################################################################

class KeccakError(Exception):
    """Class of error used in the Keccak implementation

    Use: raise KeccakError.KeccakError("Text to be displayed")"""

    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class Keccak:
    """
    Class implementing the Keccak sponge function
    """
    def __init__(self, b=1600):
        """Constructor:

        b: parameter b, must be 25, 50, 100, 200, 400, 800 or 1600 (default value)"""
        self.setB(b)

    def setB(self,b):
        """Set the value of the parameter b (and thus w,l and nr)

        b: parameter b, must be choosen among [25, 50, 100, 200, 400, 800, 1600]
        """

        if b not in [25, 50, 100, 200, 400, 800, 1600]:
            raise KeccakError.KeccakError('b value not supported - use 25, 50, 100, 200, 400, 800 or 1600')

        # Update all the parameters based on the used value of b
        self.b=b
        self.w=b//25
        self.l=int(math.log(self.w,2))
        self.nr=12+2*self.l

    # Constants

    ## Round constants
    RC=[0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008]

    ## Rotation offsets
    r=[[0,    36,     3,    41,    18]    ,
       [1,    44,    10,    45,     2]    ,
       [62,    6,    43,    15,    61]    ,
       [28,   55,    25,    21,    56]    ,
       [27,   20,    39,     8,    14]    ]

    ## Generic utility functions

    def rot(self,x,n):
        """Bitwise rotation (to the left) of n bits considering the \
        string of bits is w bits long"""

        n = n%self.w
        return ((x>>(self.w-n))+(x<<n))%(1<<self.w)

    def enc(self,x,n):
        """Encode the integer x in n bits (n must be a multiple of 8)"""

        if x>=2**n:
            raise KeccakError.KeccakError('x is too big to be coded in n bits')
        if n%8!=0:
            raise KeccakError.KeccakError('n must be a multiple of 8')
        return ("%%0%dX" % (2*n//8)) % (x)

    def fromHexStringToLane(self, string):
        """Convert a string of bytes written in hexadecimal to a lane value"""

        #Check that the string has an even number of characters i.e. whole number of bytes
        if len(string)%2!=0:
            raise KeccakError.KeccakError("The provided string does not end with a full byte")

        #Perform the modification
        temp=''
        nrBytes=len(string)//2
        for i in range(nrBytes):
            offset=(nrBytes-i-1)*2
            temp+=string[offset:offset+2]
        return int(temp, 16)

    def fromLaneToHexString(self, lane):
        """Convert a lane value to a string of bytes written in hexadecimal"""

        laneHexBE = (("%%0%dX" % (self.w//4)) % lane)
        #Perform the modification
        temp=''
        nrBytes=len(laneHexBE)//2
        for i in range(nrBytes):
            offset=(nrBytes-i-1)*2
            temp+=laneHexBE[offset:offset+2]
        return temp.upper()

    def printState(self, state, info):
        """Print on screen the state of the sponge function preceded by \
        string info

        state: state of the sponge function
        info: a string of characters used as identifier"""

        print("Current value of state: %s" % (info))
        for y in range(5):
            line=[]
            for x in range(5):
                 line.append(hex(state[x][y]))
            print('\t%s' % line)

    ### Conversion functions String <-> Table (and vice-versa)

    def convertStrToTable(self,string):
        """Convert a string of bytes to its 5x5 matrix representation

        string: string of bytes of hex-coded bytes (e.g. '9A2C...')"""

        #Check that input paramaters
        if self.w%8!= 0:
            raise KeccakError("w is not a multiple of 8")
        if len(string)!=2*(self.b)//8:
            raise KeccakError.KeccakError("string can't be divided in 25 blocks of w bits\
            i.e. string must have exactly b bits")

        #Convert
        output=[[0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0],
                [0,0,0,0,0]]
        for x in range(5):
            for y in range(5):
                offset=2*((5*y+x)*self.w)//8
                output[x][y]=self.fromHexStringToLane(string[offset:offset+(2*self.w//8)])
        return output

    def convertTableToStr(self,table):
        """Convert a 5x5 matrix representation to its string representation"""

        #Check input format
        if self.w%8!= 0:
            raise KeccakError.KeccakError("w is not a multiple of 8")
        if (len(table)!=5) or (False in [len(row)==5 for row in table]):
            raise KeccakError.KeccakError("table must be 5x5")

        #Convert
        output=['']*25
        for x in range(5):
            for y in range(5):
                output[5*y+x]=self.fromLaneToHexString(table[x][y])
        output =''.join(output).upper()
        return output

    ### Padding function

    def pad(self,M, n):
        """Pad M with reverse-padding to reach a length multiple of n

        M: message pair (length in bits, string of hex characters ('9AFC...')
        n: length in bits (must be a multiple of 8)
        Example: pad([60, 'BA594E0FB9EBBD30'],8) returns 'BA594E0FB9EBBD13'
        """

        [my_string_length, my_string]=M

        # Check the parameter n
        if n%8!=0:
            raise KeccakError.KeccakError("n must be a multiple of 8")

        # Check the length of the provided string
        if len(my_string)%2!=0:
            #Pad with one '0' to reach correct length (don't know test
            #vectors coding)
            my_string=my_string+'0'
        if my_string_length>(len(my_string)//2*8):
            raise KeccakError.KeccakError("the string is too short to contain the number of bits announced")

        #Add the bit allowing reversible padding
        nr_bytes_filled=my_string_length//8
        if nr_bytes_filled==len(my_string)//2:
            #bits fill the whole package: add a byte '01'
            my_string=my_string+"01"
        else:
            #there is no addition of a byte... modify the last one
            nbr_bits_filled=my_string_length%8

            #Add the leading bit
            my_byte=int(my_string[nr_bytes_filled*2:nr_bytes_filled*2+2],16)
            my_byte=(my_byte>>(8-nbr_bits_filled))
            my_byte=my_byte+2**(nbr_bits_filled)
            my_byte="%02X" % my_byte
            my_string=my_string[0:nr_bytes_filled*2]+my_byte

        #Complete my_string to reach a multiple of n bytes
        while((8*len(my_string)//2)%n!=0):
            my_string=my_string+'00'
        return my_string

    def Round(self,A,RCfixed):
        """Perform one round of computation as defined in the Keccak-f permutation

        A: current state (5x5 matrix)
        RCfixed: value of round constant to use (integer)
        """

        #Initialisation of temporary variables
        B=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]
        C= [0,0,0,0,0]
        D= [0,0,0,0,0]

        #Theta step
        for x in range(5):
            C[x] = A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4]

        for x in range(5):
            D[x] = C[(x-1)%5]^self.rot(C[(x+1)%5],1)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y]^D[x]

        #Rho and Pi steps
        for x in range(5):
          for y in range(5):
                B[y][(2*x+3*y)%5] = self.rot(A[x][y], self.r[x][y])

        #Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y]^((~B[(x+1)%5][y]) & B[(x+2)%5][y])

        #Iota step
        A[0][0] = A[0][0]^RCfixed

        return A

    def KeccakF(self,A, verbose=False):
        """Perform Keccak-f function on the state A

        A: 5x5 matrix containing the state
        verbose: a boolean flag activating the printing of intermediate computations
        """

        if verbose:
            self.printState(A,"Before first round")

        for i in range(self.nr):
            #NB: result is truncated to lane size
            A = self.Round(A,self.RC[i]%(1<<self.w))

            if verbose:
                  self.printState(A,"Satus end of round #%d/%d" % (i+1,self.nr))

        return A

    def Keccak(self,M,r=1024,c=576,d=0,n=1024,verbose=False):
        """Compute the Keccak[r,c,d] sponge function on message M

        M: message pair (length in bits, string of hex characters ('9AFC...')
        r: bitrate in bits (defautl: 1024)
        c: capacity in bits (default: 576)
        d: diversifier in bits (default: 0 bits)
        n: length of output in bits (default: 1024),
        verbose: print the details of computations(default:False)
        """

        #Check the inputs
        if (r<0) or (r%8!=0):
            raise KeccakError.KeccakError('r must be a multiple of 8')
        if (n%8!=0):
            raise KeccakError.KeccakError('outputLength must be a multiple of 8')
        if (d<0) or (d>255):
            raise KeccakError.KeccakError('d must be in the range [0, 255]')
        self.setB(r+c)

        if verbose:
            print("Create a Keccak function with (r=%d, c=%d, d=%d (i.e. w=%d))" % (r,c,d,(r+c)//25))

        #Compute lane length (in bits)
        w=(r+c)//25

        # Initialisation of state
        S=[[0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0],
           [0,0,0,0,0]]

        #Padding of messages
        P=self.pad(M,8) + self.enc(d,8) + self.enc(r//8,8)
        P=self.pad([8*len(P)//2,P],r)

        if verbose:
            print("String ready to be absorbed: %s (will be completed by %d x '00')" % (P, c//8))

        #Absorbing phase
        for i in range((len(P)*8//2)//r):
            Pi=self.convertStrToTable(P[i*(2*r//8):(i+1)*(2*r//8)]+'00'*(c//8))

            for y in range(5):
              for x in range(5):
                  S[x][y] = S[x][y]^Pi[x][y]
            S = self.KeccakF(S, verbose)

        if verbose:
            print("Value after absorption : %s" % (self.convertTableToStr(S)))

        #Squeezing phase
        Z = ''
        outputLength = n
        while outputLength>0:
            string=self.convertTableToStr(S)
            Z = Z + string[:r*2//8]
            outputLength -= r
            if outputLength>0:
                S = self.KeccakF(S, verbose)

            # NB: done by block of length r, could have to be cut if outputLength
            #     is not a multiple of r

        if verbose:
            print("Value after squeezing : %s" % (self.convertTableToStr(S)))

        return Z[:2*n//8]

def stringtoHex(string):
    lst = []
    for char in string:
        hexValue = hex(ord(char)).replace('0x', '')
        if len(hexValue) == 1:
            hexValue = '0' + hexValue
        lst.append(hexValue)
    return reduce(lambda x,y : x+y, lst)

def keccak256(hashInput):
    hexMsg       = stringtoHex(hashInput)
    hashfunction = Keccak()
    return hashfunction.Keccak((512, hexMsg), 1088, 512, 0, 256, 0)    # Verbose Keccak hash function presentation when checkKeyHashes is enabled

def keccakVarLen(hashInput):
    hexMsg       = stringtoHex(hashInput)
    hashfunction = Keccak()
    return hashfunction.Keccak(((8 * len(hashInput)), hexMsg), 1088, 512, 0, 256, 0)    # Verbose Keccak hash function presentation when checkKeyHashes is enabled

def keccak_encrypt(message, HexKey):

    #CTR mode, no authentication

    # Add padding to plainText, 32 for 256-bit block-size
    length    = 32 - (len(message) % 32)
    message  += chr(length) * length

    # Convert hexadecimal key to binary data
    key       = binascii.unhexlify(HexKey)

    # Generate 256-bit nonce
    nonce     = os.urandom(32)

    # Generate 512-bit IV
    iv        = (key + nonce)

    # Sponge function takes 512-bit IV, squeezes out 256 bit keystream block #1
    step      = keccak256(iv)

    i         = 0
    keystream = ''

    # For n-byte message, n/32 additional rounds is needed to generate proper length keystream
    while (i < (len(message) / 32) ):
        keystream += step
        step       = keccak256(step)
        i         += 1

    # Convert key from hex format to binary
    keystreamBIN   = binascii.unhexlify(keystream)

    # XOR keystream with plaintext to acquire ciphertext
    if len(message) == len(keystreamBIN):
        ciphertext   = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(message, keystreamBIN))
    else:
        print 'Ciphertext - keystream length mismatch (Keccak). Exiting'
        exit()


    return nonce + ciphertext



######################################################################
#                        SALSA20 STREAM CIPHER                       #
######################################################################

_salsa20 = cdll.LoadLibrary(imp.find_module('_salsa20')[1])


_stream_salsa20 = _salsa20.exp_stream_salsa20
_stream_salsa20.argtypes = [  c_char_p,  # unsigned char * c
                              c_uint64,  # unsigned long long clen
                              c_char_p,  # const unsigned char * n
                              c_char_p   # const unsigned char * k
                           ]
_stream_salsa20.restype = c_int

_stream_salsa20_xor = _salsa20.exp_stream_salsa20_xor
_stream_salsa20_xor.argtypes = [  c_char_p,  # unsigned char * c
                                  c_char_p,  # const unsigned char *m
                                  c_uint64,  # unsigned long long mlen
                                  c_char_p,  # const unsigned char * n
                                  c_char_p   # const unsigned char * k
                               ]
_stream_salsa20_xor.restype = c_int

_stream_xsalsa20 = _salsa20.exp_stream_xsalsa20
_stream_xsalsa20.argtypes = [  c_char_p,  # unsigned char * c
                               c_uint64,  # unsigned long long clen
                               c_char_p,  # const unsigned char * n
                               c_char_p   # const unsigned char * k
                            ]
_stream_xsalsa20.restype = c_int

_stream_xsalsa20_xor = _salsa20.exp_stream_xsalsa20_xor
_stream_xsalsa20_xor.argtypes = [  c_char_p,  # unsigned char * c
                                   c_char_p,  # const unsigned char *m
                                   c_uint64,  # unsigned long long mlen
                                   c_char_p,  # const unsigned char * n
                                   c_char_p   # const unsigned char * k
                                ]
_stream_xsalsa20_xor.restype = c_int


IS_PY2 = sys.version_info < (3, 0, 0, 'final', 0)

def _ensure_bytes(data):
    if (IS_PY2 and not isinstance(data, str)) or (not IS_PY2 and not isinstance(data, bytes)):
        raise TypeError('can not encrypt/decrypt unicode objects')

def Salsa20_keystream(length, nonce, key):
    _ensure_bytes(nonce)
    _ensure_bytes(key)
    if not len(key) == 32: raise ValueError('invalid key length')
    if not len(nonce) == 8: raise ValueError('invalid nonce length')
    if not length > 0: raise ValueError('invalid length')

    outbuf = create_string_buffer(length)
    _stream_salsa20(outbuf, length, nonce, key)
    return outbuf.raw

def Salsa20_xor(message, nonce, key):
    _ensure_bytes(nonce)
    _ensure_bytes(key)
    _ensure_bytes(message)
    if not len(key) == 32: raise ValueError('invalid key length')
    if not len(nonce) == 8: raise ValueError('invalid nonce length')
    if not len(message) > 0: raise ValueError('invalid message length')

    outbuf = create_string_buffer(len(message))
    _stream_salsa20_xor(outbuf, message, len(message), nonce, key)
    return outbuf.raw

def XSalsa20_keystream(length, nonce, key):
    _ensure_bytes(nonce)
    _ensure_bytes(key)
    if not len(key) == 32: raise ValueError('invalid key length')
    if not len(nonce) == 24: raise ValueError('invalid nonce length')
    if not length > 0: raise ValueError('invalid length')

    outbuf = create_string_buffer(length)
    _stream_xsalsa20(outbuf, length, nonce, key)
    return outbuf.raw

def XSalsa20_xor(message, nonce, key):
    _ensure_bytes(nonce)
    _ensure_bytes(key)
    _ensure_bytes(message)
    if not len(key) == 32: raise ValueError('invalid key length')
    if not len(nonce) == 24: raise ValueError('invalid nonce length')
    if not len(message) > 0: raise ValueError('invalid message length')

    outbuf = create_string_buffer(len(message))
    _stream_xsalsa20_xor(outbuf, message, len(message), nonce, key)
    return outbuf.raw

def salsa_20_encrypt(plaintext, hexKey):

    # Convert uppercase hex to lowercase
    hexKey      = hexKey.lower()

    # Convert hexadecimal key to bitstring
    key         = binascii.unhexlify(hexKey)

    # Generate unique nonce
    nonce       = os.urandom(24)

    # XOR plaintext with keystream to acquire ciphertext
    ciphertext  = XSalsa20_xor(plaintext, nonce, key)

    return nonce + ciphertext



######################################################################
#                        TWOFISH BLOCK CIPHER                        #
######################################################################

_twofish = cdll.LoadLibrary(imp.find_module('_twofish')[1])

class _Twofish_key(Structure):
    _fields_ = [("s", (c_uint32 * 4) * 256),
                ("K", c_uint32 * 40)]

_Twofish_initialise = _twofish.exp_Twofish_initialise
_Twofish_initialise.argtypes = []
_Twofish_initialise.restype = None

_Twofish_prepare_key = _twofish.exp_Twofish_prepare_key
_Twofish_prepare_key.argtypes = [ c_char_p,  # uint8_t key[]
                                  c_int,     # int key_len
                                  POINTER(_Twofish_key) ]
_Twofish_prepare_key.restype = None

_Twofish_encrypt = _twofish.exp_Twofish_encrypt
_Twofish_encrypt.argtypes = [ POINTER(_Twofish_key),
                              c_char_p,     # uint8_t p[16]
                              c_char_p      # uint8_t c[16]
                            ]
_Twofish_encrypt.restype = None

_Twofish_decrypt = _twofish.exp_Twofish_decrypt
_Twofish_decrypt.argtypes = [ POINTER(_Twofish_key),
                              c_char_p,     # uint8_t c[16]
                              c_char_p      # uint8_t p[16]
                            ]
_Twofish_decrypt.restype = None

_Twofish_initialise()

IS_PY2 = sys.version_info < (3, 0, 0, 'final', 0)

def _ensure_bytes(data):
    if (IS_PY2 and not isinstance(data, str)) or (not IS_PY2 and not isinstance(data, bytes)):
        raise TypeError('can not encrypt/decrypt unicode objects')


class Twofish():
    def __init__(self, key):
        if not (len(key) > 0 and len(key) <= 32):
            raise ValueError('invalid key length')
        _ensure_bytes(key)

        self.key = _Twofish_key()
        _Twofish_prepare_key(key, len(key), pointer(self.key))

    def encrypt(self, data):
        if not len(data) == 16:
            raise ValueError('invalid block length')
        _ensure_bytes(data)

        outbuf = create_string_buffer(len(data))
        _Twofish_encrypt(pointer(self.key), data, outbuf)
        return outbuf.raw

    def decrypt(self, data):
        if not len(data) == 16:
            raise ValueError('invalid block length')
        _ensure_bytes(data)

        outbuf = create_string_buffer(len(data))
        _Twofish_decrypt(pointer(self.key), data, outbuf)
        return outbuf.raw


# Repeat the test on the same vectors checked at runtime by the library
def self_test():

    # 128-bit test is the I=3 case of section B.2 of the Twofish book.
    t128 = ('9F589F5CF6122C32B6BFEC2F2AE8C35A',
        'D491DB16E7B1C39E86CB086B789F5419',
        '019F9809DE1711858FAAC3A3BA20FBC3')

    # 192-bit test is the I=4 case of section B.2 of the Twofish book.
    t192 = ('88B2B2706B105E36B446BB6D731A1E88EFA71F788965BD44',
        '39DA69D6BA4997D585B6DC073CA341B2',
        '182B02D81497EA45F9DAACDC29193A65')

    # 256-bit test is the I=4 case of section B.2 of the Twofish book.
    t256 = ('D43BB7556EA32E46F2A282B7D45B4E0D57FF739D4DC92C1BD7FC01700CC8216F',
        '90AFE91BB288544F2C32DC239B2635E6',
        '6CB4561C40BF0A9705931CB6D408E7FA')

    for t in (t128, t192, t256):
        k = binascii.unhexlify(t[0])
        p = binascii.unhexlify(t[1])
        c = binascii.unhexlify(t[2])

        T = Twofish(k)
        if not T.encrypt(p) == c or not T.decrypt(c) == p:
            raise ImportError('the Twofish library is corrupted')


def twofish_encrypt(plainText, HexKey):

    # Add padding to plainText
    length     = 16 - (len(plainText) % 16)
    plainText += chr(length) * length

    # Convert uppercase hex to lowercase
    HexKey    = HexKey.lower()

    # Convert hexadecimal key to binary data
    key       = binascii.unhexlify(HexKey)

    # Keystream blocks equals the number of CT blocks
    msgArray  = [plainText[i:i + 16] for i in range(0, len(plainText), 16)]

    # Generate unique nonce
    nonce     = os.urandom(16)

    # n.o. keystream blocks equals the n.o. CT blocks
    msgA      = [plainText[i:i + 16] for i in range(0, len(plainText), 16)]

    keystream = ""
    counter   = 1

    for block in msgA:

        # Convert integer counter to unique 16-byte counter
        binrep     = str(bin(counter))[2:].zfill(128)
        ctr        = ''.join(chr(int(binrep[i:i+8], 2)) for i in xrange(0, len(binrep), 8))

        # XOR 128-bit nonce with 128-bit counter to change nonce-input of Twofish cipher
        iv         = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(ctr, nonce))

        # Initialize Twofish cipher with key
        E           = Twofish(key)

        # Encrypt unique IV with key
        keyBlock    = E.encrypt(iv)

        # Append new block to keystream
        keystream  += keyBlock

        # Iterate the counter of randomized CTR mode
        counter    += 1

    # XOR keystream with plaintext to acquire ciphertext
    if len(plainText) == len(keystream):
        ciphertext = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(plainText, keystream))
    else:
        print 'Ciphertext - keystream length mismatch (Twofish). Exiting'
        exit()

    return nonce + ciphertext



######################################################################
#     AES (GCM) AUTHENTICATED ENCRYPTION (RIJNDAEL BLOCK CIPHER)     #
######################################################################


def writeNonce(nonce):
    with open('usedNonces.tfc', 'a+') as uNlist:
        uNlist.write( b64e(nonce) + '\n' )

def nonce_is_blacklisted(nonce):
    b64r = b64e(nonce)
    try:
        with open('usedNonces.tfc', 'r') as uNlist:
            for line in uNlist:
                if b64r in line:
                    os.system('clear')
                    return True
                else:
                    if debugging:
                        print 'M(nonce_not_blacklisted):\nNonce was not blacklisted\n'
                    return False
    except IOError:
        return False

def AES_GCM_encrypt(plaintext, hexKey):
    AESkey        = binascii.unhexlify(hexKey)
    nonce         = get_random_bytes(64)

    while nonce_is_blacklisted(nonce):
        nonce     = get_random_bytes(64)

    writeNonce(nonce)
    cipher        = AES.new(AESkey, AES.MODE_GCM, nonce)
    cipher.update('')

    ctArray       = nonce, cipher.encrypt(plaintext), cipher.digest()
    ciphertext    = ""

    # convert list to string
    for i in ctArray:
        ciphertext += i

    if debugging:
        print 'M(encrypt): Using following parameters:'
        print '  Nonce   (len =  ' + str(len(nonce) * 8) + ' bits): "' + nonce + '"'
        print '  AES-key (len = '  + str(len(key)   * 8) + ' bits): "' + key   + '"'
        print '  Plaintext: "'     + plaintext                                 + '"'

    # print '\n\nciphertext ' + binascii.hexlify(ciphertext)
    return ciphertext

######################################################################
#                      DIFFIE-HELLMAN KEY EXCHANGE                   #
######################################################################

class DiffieHellman(object):
    prime     = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
    generator = 2


    def __init__(self):
        self.privateKey = self.genPrivateKey(576)
        self.publicKey = self.genPublicKey()



    def genPrivateKey(self, bits):
        return secure_random(bits)



    def genPublicKey(self):
        return pow(self.generator, self.privateKey, self.prime)



    def checkPublicKey(self, otherKey):
        if(otherKey > 2 and otherKey < self.prime - 1):
            if(pow(otherKey, (self.prime - 1)/2, self.prime) == 1):
                return True
        return False



    def genSecret(self, privateKey, otherKey):
        if(self.checkPublicKey(otherKey) == True):
            sharedSecret = pow(otherKey, privateKey, self.prime)
            return sharedSecret
        else:
            raise Exception("Invalid public key.")



    def genKey(self, otherKey):
        self.sharedSecret = self.genSecret(self.privateKey, otherKey)
        s = hashlib.sha256()
        s.update(str(self.sharedSecret))
        self.key = s.digest()



    def getKey(self):
        return self.key



def validateInput(string):

    # Verify that length is 64 characters
    StaticLength = 64
    if ( len(string) != StaticLength ):
        print 'Illegal length. Hex value must be 64 long'
        return False

    # Verify that each character is a hex-value
    allowedChars = [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' ]
    for c in string:
        if c not in allowedChars:
            print 'Illegal char. Allowed chars: 0123456789abcdef'
            return False

    # Calculate the checksum remotely and ask confirmation from user
    checksum = crc32(string)
    answer   = ''
    while (answer != 'YES') and (answer != 'NO'):
        answer = raw_input('\nIs the checksum of shared secret on RxM ' + checksum + '? Type \'YES\' or \'NO\': ')
    
        if (answer == 'NO'):
            print 'Illegal checksum'
            return False   
        if (answer == 'YES'):
            return True



def dhe_process(xmpp):

    # Generate DH-keypair
    b         = DiffieHellman()
    dhPk      = str(b.privateKey)
    publicKey = 'DH_PUBKEY_' + str(b.publicKey)
    os.system('clear')

    #print private DH key
    print '\n1. Private DH key for RxM: '
    pkNl = [dhPk[i:i+10] for i in range(0, len(dhPk), 10)]
    c = 1
    for i in pkNl:
        print 'block ' + str(c)+':    ' + i + crc32(i)[-3:]
        c += 1

    print '\n2. CRC checksum of your private key: ' + crc32(dhPk)

    # Transmit public key
    if not longMessageProcess(publicKey, xmpp):
        print 'Key exchange failed. Aborting'
        return 'Warning: Key exchange failed'

    # User entry of shared secret key
    print 'WARNING! You must now type the shared secret key (ssk) from RxM to TxM.'
    print 'Before typing, please make sure the key RxM displays, only contains'
    print 'characters 0123456789abcdef. If this is not the case, do not proceed!'

    ssk = raw_input('\n3. Type the shared secret key : ')
    while not validateInput(ssk):
        ssk = raw_input('\n3. Type the shared secret key : ')

    # Input secret to salt hash of DH shared secret key
    os.system('clear')
    print '5. Since we are assuming adversary is already in control of all deterministic keys\ncurrently in use, hash of public key needs to be verified manually. Call your contact\nand on the phone, agree on a secret that is hard for adversary to guess.'
    print '\n\n                         DO NOT SAY THE SECRET ALOUD!'


    salt     = raw_input('\n6. Enter the secret, that was agreed on: ')
    pKeyHash = keccakVarLen(salt + ssk)
    hashSpc  = ' '.join(pKeyHash[i:i+8] for i in xrange(0,len(pKeyHash),8))

    print '\n7. Read the following hash taking variable length turns.'
    print '   If the hashes match, risk of MITM should be very low.\n'
    print '   ' + hashSpc

    pkk  = str(b.publicKey)
    ssk2 = keccakVarLen(ssk + pkk[:20])

    success = ""
    while (success != 'VERIFIED') and (success != 'MISMATCH'):
        success = raw_input('\nIf the hash was a match, type  \'VERIFIED\' , else type \'MISMATCH\': ')
    if (success == 'VERIFIED'):
        DH_Write_Key(xmpp, ssk2)
        os.system('clear')
        print 'DHE finished succesfully'
    if (success == 'MISMATCH'):
        os.system('clear')
        print 'DHE aborted. Continuing with old keys'
        pass

def DH_Write_Key(xmpp, ssk2):
    keys = get_xmpp_keyset(xmpp)

    keys[3] = ssk2
    with open(xmpp + '.e', 'w+') as efile:
        for key in keys:
            efile.write(key + '\n')



######################################################################
#                        KEY MANAGEMENT FUNCTIONS                    #
######################################################################

def store_keyID(xmpp, keyID):
    contacts = []
    with open('txc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)

    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
           contacts[i][2] = keyID

    with open('txc.tfc', 'w') as cFile:
        writer = csv.writer(cFile)
        writer.writerows(contacts)

    if debugging:
        print '\nM(store_keyID): Wrote line \'' + str(keyID) + '\' for contact ' + xmpp + ' to txc.tfc\n'



def get_keyID(xmpp):
    contacts = []
    with open('txc.tfc', 'r') as cFile:
        csvData = csv.reader(cFile)
        for row in csvData:
            contacts.append(row)

    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
            keyID = int(contacts[i][2])
            return keyID

    print 'ERROR: Failed to load keyID for XMPP ' + xmpp + '. Exiting'
    exit()



def get_xmpp_keyset(xmpp):
    with open(xmpp + '.e') as efile:
        keyFile = efile.readlines()
    keys = []
    for key in keyFile:
        key = key.strip('\n')
        keys.append(key)
    if (len(keys) < 4):
        print 'Warning! Failed to load 4 keys from keyfile ' + xmpp + '.e. Exiting!'
        exit()
    if debugging:
        print 'M(get_xmpp_keyset):\nLoaded following set of key for xmpp ' + xmpp
        for item in keys:
            print item
    return keys



def get_local_keyset():
    return get_xmpp_keyset('tx.local')



def rotateKeys(xmpp):
    keySet = get_xmpp_keyset(xmpp)
    for key in keySet:
        if (len(key) != 64):
            print 'WARNING, KEYFILE KEY ERROR. EXITING'
            exit()

    with open(xmpp + '.e', 'w+') as efile:
        for key in keySet:
            nKey = keccak256(key)
            efile.write(nKey + '\n')



def encrypt(xmpp, pt):

    keySet  = get_xmpp_keyset(xmpp)

    ct1 = keccak_encrypt   (pt,  keySet[0])
    ct2 = salsa_20_encrypt (ct1, keySet[1])
    ct3 = twofish_encrypt  (ct2, keySet[2])
    ct4 = AES_GCM_encrypt  (ct3, keySet[3])

    rotateKeys(xmpp)

    return ct4



######################################################################
#                              SETTERS                               #
######################################################################

def add_new_contacts(entropyfilenames):
    contacts   = []
    datareader = csv.reader(open('txc.tfc', 'a+'))
    for row in datareader:
        contacts.append(row)
    for item in entropyfilenames:
        onList = False
        xmpp   = item[:-2]
        for person in contacts:
            if xmpp in person[1]:
                onList = True
        if not onList:
            if (xmpp == 'tx.local'):
                add_contact('txlocal', 'tx.local')
            else:
                newNick  = raw_input('New contact ' + xmpp + ' found. Enter nick: ')
                add_contact(newNick, xmpp)



def add_contact(nick, xmpp):
    contacts = []
    with open('txc.tfc', 'a+') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)
        cFile.write(nick + ',' + xmpp + ',1\n')
    if debugging:
        print '\nM(add_contact):\nAdded contact ' + nick + ' (xmpp = ' + xmpp + ') to txc.tfc\n'



def write_nick(xmpp, nick):
    contacts = []
    with open ('txc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)
        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
               contacts[i][0] = nick
    with open('txc.tfc', 'w') as cFile:
        writer = csv.writer(cFile)
        writer.writerows(contacts)
    if debugging:
        print '\nM(write_nick):\nWrote nick ' + nick + ' for account ' + xmpp + ' to txc.tfc\n'



######################################################################
#                           GROUP RELATED                            #
######################################################################

def create_group_list(group, newMembers = []):
    fileExists = os.path.isfile('g.' + group + '.tfc')
    if fileExists:
        if not (raw_input('\nGroup called \'' + group + '\' already exists. Type YES to overwrite: ') == 'YES'):
            return False
    with open('g.' + group + '.tfc', 'w+') as gFile:
        if newMembers:
            for member in newMembers:
                member = member.strip(' ')
                if (member != ''):
                    gFile.write(member + '\n')
    sort_group(group)
    return True



def add_to_groupList(group, addList):
    alreadyExisting = []
    notAdded        = []
    with open('g.' + group + '.tfc', 'a+') as gFile:
        lines    = gFile.readlines()

    for line in lines:
        line = line.strip('\n')
        alreadyExisting.append(line)

    print '\nAdded following members to group \'' + group + '\':'
    for item in addList:
        item = item.strip('\n')
        item = item.strip(' ')

        if not item in alreadyExisting:
            if (item != ''):
                gFile.write(item + '\n')
                print '   ' + item
        else:
            notAdded.append(item)
    if notAdded:
        print '\nFollowing contacts already existed in group \'' + group + '\' and were thus not added:'
        for item in notAdded:
            print '   ' + item
    print ''
    sort_group(group)



def rem_from_groupList(group, rmList):
    memberList = []
    notRemoved = []
    printing   = False
    with open('g.' + group + '.tfc', 'r') as gFile:
        readLines = gFile.readlines()
    for line in readLines:
        member = line.strip('\n')
        memberList.append(member)

    print '\nRemoved from group \'' + usedGroup + '\' following members:'
    with open('g.' + group + '.tfc', 'w') as gFile:
        for member in memberList:
            if member in rmList:
                print '   ' + member
            else:
                gFile.write(member + '\n')          # Write remaining group members back to file.

        for rmItem in rmList:                       # Check if user tried to remove members not in the group file.
            if not rmItem in memberList:
                if (str(rmItem) != ''):
                    notRemoved.append(rmItem)
                    printing = True
        if printing:
            print '\nFollowing accounts were not in group \'' + group + '\' and were thus not removed:'
            for remUser in notRemoved:
                print '   ' + remUser
        print ''



def sort_group(group):
    with open('g.' + group + '.tfc', 'r') as gFile:
        members = gFile.readlines()
        members.sort()
    with open('g.' + group + '.tfc', 'w') as gFile:
        for item in members:
            gFile.write(item)



def get_group_file_list(output):
    gFileNames = []
    for fileN in os.listdir('.'):
        if fileN.startswith('g.') and fileN.endswith('.tfc'):
            gName = fileN[2:][:-4]
            gname = gName.strip('\n')
            gFileNames.append(gName)

    if output:
        if not gFileNames:
            print '\nThere are currently no groups'
    return gFileNames



def get_group_members(groupName):
    groupList = []
    with open('g.' + groupName + '.tfc', 'r+') as gFile:
        fLines = gFile.readlines()
    for line in fLines:
        groupList.append(line.strip('\n'))

    if not groupList:
        print '\nLoaded empty group. Add contacts to group with command\n   /group add <group> <xmpp>\n'
    return groupList



######################################################################
#                              GETTERS                               #
######################################################################

def get_contact_quantity():
    with open('txc.tfc', 'r') as contactFile:
        for i, l in enumerate(contactFile):
            pass

    with open('txc.tfc', 'r') as contactFile:
        for line in contactFile:
                if str('tx.local') in line: # If tx.local.e is available, number of contacts
                    return i                # is 1 lower than items in contact list.
    return i + 1                            # Since indexing starts from 0, add 1 to get number of contacts.



def get_entropy_file_list():
    entFileL = []
    xmppAddL = []
    for fileN in os.listdir('.'):
        if fileN.endswith('.e'):
            if not fileN.startswith('me.') and not fileN.startswith('rx.'):
                entFileL.append(fileN)
                xmppAddL.append(fileN[:-2][3:])
    return entFileL, xmppAddL



def get_nick(xmpp):
    contacts = []
    with open('txc.tfc', 'r') as cFile:
        csvData = csv.reader(cFile)
        for row in csvData:
            contacts.append(row)
    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
            nick = contacts[i][0]
            return nick
    print 'ERROR: Failed to load nick for XMPP ' + xmpp + '. Exiting'
    exit()



def get_autotabs(contacts):
    aTabContacts = []
    for item in contacts:
        aTabContacts.append(item + ' ')
    aTabGfiles   = []
    gFileList    = get_group_file_list(False)
    for item in gFileList:
        aTabGfiles.append(item + ' ')

    cList        = ['about', 'add ', 'clear', 'create ', 'exit', 'file ', 'group ', 'help', 'logging ', 'msg ', 'newkf ', 'nick ', 'quit', 'rm ', 'select ']

    return aTabContacts + aTabGfiles + cList



######################################################################
##                              CHECKS                              ##
######################################################################

def search_contact_keyfiles():
    keyfiles  = []
    keyfiles += [each for each in os.listdir('.') if each.endswith('.e')]
    if not keyfiles:
        os.system('clear')
        print '\nError: No keyfiles for contacts were found. Make sure they are in same directory as Tx.py\n'
        exit()



def search_local_e_kf():
    try:
        with open('tx.local.e'):
            pass
        return True
    except IOError:
        print 'Error: tx.local.e was not found'
        return False



######################################################################
#                           PACKET OUTPUT                            #
######################################################################

def output_command(base64msg, line, crc):
    if localTesting:
        with open('TxOutput', 'w+') as txOut:
            txOut.write('<ctrl>'                                                                        + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_command): Writing following command to file \'TxOutput\':\n<ctrl>'        + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''
    else:
        port.write('<ctrl>'                                                                             + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_command): Transferring following command to NH:\n<ctrl>'                  + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''


def output_message(xmpp, base64msg, line, crc):
    if localTesting:
        with open('TxOutput', 'w+') as txOut:
            txOut.write(                                                      '<mesg>' + xmpp[3:] + '~' + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_message): Writing msg to file \'TxOutput\':\n<mesg>'     + xmpp     + '~' + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''

    else:
        port.write(                                                           '<mesg>' + xmpp[3:] + '~' + base64msg + '|' + str(line) + '~' + crc + '\n')
        if debugging:
            print '\nM(output_message): Transferring following message to NH:\n<mesg>' + xmpp     + '~' + base64msg + '|' + str(line) + '~' + crc + '\n'
            print ''



######################################################################
#                           MSG PROCESSING                           #
######################################################################

def b64e(content):
    return base64.b64encode(content)



def crc32(content):
    return str(hex(zlib.crc32(content)))



def padding(string):
    while (len(string) % PkgSize != 0):
        string = string + ' '
    if debugging:
        print '\n\nM(padding): Padded input to length of ' + str( len(string) ) +' chars:\n"""' + string + '"""\n'
    return string



######################################################################
#                       COMMANDS AND FUNCTIONS                       #
######################################################################

def tab_complete(text, state):
    options = [x for x in autotabs if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None



def multiPacketProcess(string):
    string      = string.strip('\n')
    msgA        = [string[i:i + (PkgSize-1)] for i in range(0, len(string), (PkgSize-1) )]
    for i in xrange( len(msgA) ):
        msgA[i] = 'a' + msgA[i]               # 'a' tells Rx.py the message should be appended to long message
    msgA[-1]    = padding('e' + msgA[-1][1:]) # 'e' tells Rx.py the message is last one of long message, so Rx.py knows it can show the entire message.
    msgA[0]     = msgA[0][1:]
    msgA[0]     = 'l' + msgA[0]               # 'l' tells Rx.py the message is going to be long than standard, otherwise all standard messages start with 's' (=short message).
    if debugging:
        print 'M(multiPacketProcess): Processed long message to following list:'
        for item in msgA:
            print '"""' + item + '"""'
    return msgA



def longMessageProcess(kb, xmpp):
    if len(kb) > (PkgSize - 3):
        msglist  = multiPacketProcess(kb)
        halt     = False
        print '\nTransferring message in ' + str( len(msglist) ) + ' parts. ^C cancels'
        for partOfMsg in msglist:
            if halt:
                if kb.startswith('TFCFILE'):
                    print '\File transmission interrupted by user\n'
                else:
                    print '\nMessage transmission interrupted by user\n'
                return False
            try:
                ciphertext = encrypt(xmpp, partOfMsg)
                encoded    = b64e (ciphertext)
                line       = get_keyID(xmpp)
                crcPacket  = crc32(encoded + '|' + str(line))
                store_keyID(xmpp, line+1)

                output_message(xmpp, encoded, line, crcPacket)
                if randomSleep:
                    sleepTime = random.uniform(0, maxSleepTime)
                    print 'Sleeping ' + str(sleepTime) + ' seconds for randomness'
                    sleep(sleepTime)
                sleep(lMsgSleep)
            except (KeyboardInterrupt):
                halt = True
    return True



def shortMessageProcess(kb, xmpp):
    padded     = padding('s' + kb)      # 's' tells Rx.py the message can be displayed immediately (unlike long messages).
    ciphertext = encrypt(xmpp, padded)
    encoded    = b64e (ciphertext)
    line       = get_keyID(xmpp)
    crcPacket  = crc32(encoded + '|' + str(line))
    store_keyID(xmpp, line+1)
    output_message(xmpp, encoded, line, crcPacket)
    return True



def commandMessageProcess(cmdMsg):
    ciphertext      = encrypt('tx.local', cmdMsg)
    encoded         = b64e (ciphertext)
    line            = get_keyID('tx.local')
    crcPacket       = crc32(encoded + '|' + str(line))
    store_keyID('tx.local', line+1)
    output_command(encoded, line, crcPacket)
    return True



def quitProcess(output=False):
    os.system('clear')
    if output:
        print 'Exiting TFC'
    if localTesting:
        with open('TxOutput', 'w+') as txout:
            txout.write('exitTFC\n')
    else:
        port.write('exitTFC\n')
    exit()



def print_help():
    ttyW = int(subprocess.check_output(['stty', 'size']).split()[1]) #Scale help output with terminal size

    if ttyW < 65:
        le = '\n' + ttyW * '-'
        print                                                                   le
        print '/about\nDisplay information about TFC'                         + le
        if not emergencyExit:
            print '/clear & \'  \'\nClear screens'                            + le
        if emergencyExit:
            print '\'  \'\nEmergency exit'                                    + le
            print '/clear\nClear screens'                                     + le
        print '/help\nDisplay this list of commands'                          + le
        print '/logging <on/off>\nEnable/disable logging'                     + le
        print '/msg <ID/xmpp/group>\nChange recipient'                        + le
        print '/names\nDisplays available contacts'                           + le
        print '/paste\nEnable paste-mode'                                     + le
        print '/file <filename>\nSend file to recipient'                      + le
        print '/nick <nick>\nChange contact nickname'                         + le
        print '/quit & /exit\nExit TFC'                                       + le
        print '/dhe\nInitiate Diffie-Hellman key exchange'                    + le
        print '/group\nList group members'                                    + le
        print '/groups\nList available groups'                                + le
        print '/group <groupname>\nSelect group'                              + le
        print '/group create <groupname> <xmpp1> <xmpp2>\nCreate new group'   + le
        print '/group add <groupname> <xmpp1> <xmpp2>\nAdd xmpp to group'     + le
        print '/group rm <groupname> <xmpp1> <xmpp2>\nRemove xmpp from group' + le
        print '/shift+PgUp/PgDn\nScroll terminal up/dn'                       + le
        print ''
        
    else:
        print       'List of commands:'
        print       ' /about'                                      + 16 * ' ' + 'Show information about software'
        if emergencyExit:
            print   ' /clear'                                      + 16 * ' ' + 'Clear screens'
            print   ' \'  \' (2x spacebar) '                                  + 'Emergency exit'
        else:
            print   ' /clear & \'  \''                             + 9  * ' ' + 'Clear screens'
        print       ' /help'                                       + 17 * ' ' + 'Display this list of commands'
        print       ' /logging <on/off>'                           + 5  * ' ' + 'Enable/disable logging on Rx.py'
        print       ' /msg <ID/xmpp/group>'                        + 2  * ' ' + 'Change recipient (use with /names)'
        print       ' /names'                                      + 16 * ' ' + 'Displays available contacts'
        print       ' /paste'                                      + 16 * ' ' + 'Enable paste-mode'
        print       ' /file <filename>'                            + 6  * ' ' + 'Send file to recipient'
        print       ' /nick <nick>'                                + 10 * ' ' + 'Change contact\'s nickname on Tx.py & Rx.py'
        print       ' /quit & /exit'                               + 9  * ' ' + 'Exits TFC'
        print       ' /dhe'                                        + 18 * ' ' + 'Initiate Diffie-Hellman key exchange'
        print       ' /group'                                      + 16 * ' ' + 'List group members'
        print       ' /groups'                                     + 15 * ' ' + 'List available groups'
        print       ' /group <groupname>'                          + 4  * ' ' + 'Select group\n'
        print       ' /group create <groupname> <xmpp1> <xmpp2>'   + 5  * ' ' + '\n Create new group called <groupname>, add list of xmpp-addresses.\n'
        print       ' /group add <groupname> <xmpp1> <xmpp2>'      + 8  * ' ' + '\n Add xmpp-addresses to group <groupname>\n'
        print       ' /group rm <groupname> <xmpp1> <xmpp2>'       + 8  * ' ' + '\n Remove xmpp-addresses from group <groupname>\n'
        print       ' shift + PgUp/PgDn'                           + 5  * ' ' + 'Scroll terminal up/down\n'


######################################################################
#                         CONTACT SELECTION                          #
######################################################################

def print_list_of_contacts():
    ttyW        = int(subprocess.check_output(['stty', 'size']).split()[1]) #Get terminal width
    nicks       = []
    for xmpp in entropyfilenames:
        nick    = get_nick(xmpp[:-2])
        nicks.append(nick)
    if  'tx.local' in nicks:
        nicks.remove('tx.local')
    gap         = (len(max(entropyfilenames, key=len))  - 2) - len('XMPP-addr')
    header      = 'XMPP-addr' + gap * ' ' + 'ID  Nick'
    maxWidth    = len(header)
    if ttyW >= maxWidth:
        print header
        print ttyW * '-'

    for xmpp in entropyfilenames:
        iD      = entropyfilenames.index(xmpp)
        nick    = get_nick(xmpp[:-2])
        xmpp    = xmpp[:-2][3:]
        if nick != 'txlocal':
            dst1 = int(header.index('I')) - len(xmpp)                                              # Dev note: This will cause problems with translations
            dst2 = int(header.index('N')) - len(xmpp) - dst1 - len(str(iD))                        # Try to name header names so that each
            print xmpp + dst1 * ' ' + str(iD) + dst2 * ' ' + nick
        idSelDist = int(header.index('I'))

    return maxWidth, idSelDist # Return values that tell select_contact where to place the cursor for selection




def select_contact(maxWidth, idSelDist, contactNoParameter='', menu=True):
    while True:
        if contactNoParameter == '':
            try:
                ttyW = int(subprocess.check_output(['stty', 'size']).split()[1])
                if ttyW < maxWidth:
                    contactNumber = int(raw_input('\nSelect ID:  '))
                else:
                    contactNumber = int(raw_input('\nSelect contact:' + (idSelDist - len('Select contact') - 1) * ' ') )

                if contactNumber > get_contact_quantity():
                    if menu:
                        os.system('clear')
                        print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
                        print_list_of_contacts()
                        continue
                    else:
                        raise ValueError, 'Invalid number'
            except ValueError:
                if menu:
                    os.system('clear')
                    print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
                    print_list_of_contacts()
                    continue
                else:
                    raise ValueError, 'Invalid number'
            except KeyboardInterrupt:
                os.system('clear')
                print 'Exiting TFC'
                exit()

        else:
            contactNumber   = contactNoParameter

        try:
            entropyfile     = entropyfilenames[contactNumber]
        except IndexError:
            os.system('clear')
            print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
            print_list_of_contacts()
            continue
        xmpp                = entropyfile[:-2]
        nick                = get_nick(xmpp)

        if xmpp == 'tx.local':
            if menu:
                contactNoParameter = ''
                os.system('clear')
                print 'TFC ' + version + '\n\nError: Invalid contact selection\n'
                print_list_of_contacts()
                continue
            else:
                print '\nError: Can\'t select local as contact\n'
                raise ValueError

        return xmpp, nick



######################################################################
#                              PRE LOOP                              #
######################################################################

pastemode         = False
noMsgkeys_Rem_chk = False
usedCommand       = False
transferringFile  = False

search_contact_keyfiles()

# Get local.e related data
local_e_available   = search_local_e_kf()

# Get contact related data
entropyfilenames, contacts = get_entropy_file_list()
add_new_contacts(entropyfilenames)

# Group related
groupName     = ''
groupFileList = get_group_file_list(False)

# Autotabbing
readline.set_completer(tab_complete)
readline.parse_and_bind('tab: complete')

os.system('clear')
print 'TFC ' + version + 3 * '\n'

# Contact selection
maxWidth, idSelDist  = print_list_of_contacts()
xmpp, nick = select_contact(maxWidth, idSelDist)



######################################################################
#                                LOOP                                #
######################################################################

os.system('clear')

while True:

    autotabs      = get_autotabs(contacts)
    groupFileList = get_group_file_list(False)

    if pastemode:
        try:
            os.system('clear')
            print 'You\'re now in paste mode:\n2x ^D sends message.\n   ^C exits paste mode.\n'
            print 'paste content to ' + nick + ':\n'
            inPt = sys.stdin.readlines()
            kb   = '\n' + ''.join(inPt)
            print '\nSending...'
            sleep(0.1)

        except KeyboardInterrupt:
            pastemode = False
            kb        = ''
            print 'Exiting paste mode...'
            sleep(0.5)
            os.system('clear')
            continue

    if not pastemode:
        try:
            kb = raw_input(' msg to ' + nick + ': ' )
        except KeyboardInterrupt:
            os.system('clear')
            print 'Exiting TFC'
            exit()

    usedCommand = True  # First we assume that input was a command



    ##################################################################
    #                       LOCAL GROUP COMMANDS                     #
    ##################################################################

    # List group members
    if (kb in ['/group', '/group ']):
        if (groupName == ''):
            print '\nNo group selected\n'
            continue
        activeGroup = get_group_members(groupName)
        if activeGroup:
            os.system('clear')
            print '\nMembers of selected group \'' + groupName + '\':'
            for member in activeGroup:
                print '   ' + member
            print ''
        continue


    # List available groups
    if (kb == '/groups'):
        groupFileList = get_group_file_list(True)
        if groupFileList:
            os.system('clear')
            print '\nAvailable groups are: '
            for group in groupFileList:
                print '   ' + group
        print ''
        continue


    # Create new group
    if kb.startswith('/group create '):
        while kb.endswith(' '):
            kb = kb[:-1]

        # Group can't have same name as command or contact nick
        reservedNames = ['create', 'add', 'rm']
        for addr in entropyfilenames:
            member = get_nick(addr[:-2])
            reservedNames.append(member)

        # Check that group name is not reserved or empty
        newGroupName = kb.split(' ')[2]
        if (newGroupName == ''):
            print '\nError: Group name can\'t be empty\n'
            continue
        if newGroupName in reservedNames:
            print '\nError: Reserved string as group name\n'
            continue

        # Iterate through contacts to be added
        members = []
        i       = 3
        os.system('clear')
        while i <= (len(kb.split(' ')) - 1):
            newMember = kb.split(' ')[i]
            i += 1
            mbrFile = 'tx.' + newMember + '.e'
            if (mbrFile in ['tx.local.e', 'rx.local.e']) or mbrFile not in entropyfilenames:
                print '\nError: Contact \'' + newMember + '\' was not accepted to group ' + newGroupName + '\n'
                continue
            members.append(newMember)

        # Print information about creating
        if create_group_list(newGroupName, members):
            if members:
                print '\nCreated group \'' + newGroupName + '\' with following members:'
                for member in members:
                    if (member != ''):
                        print '   ' + member
            else:
                print '\nCreated group ' + newGroupName
            print ''
            continue
        else:
            print '\nGroup generation cancelled\n'
            continue


    # Add member to group
    if kb.startswith('/group add '):
        while kb.endswith(' '):
            kb    = kb[:-1]
        usedGroup = kb.split(' ')[2]
        if not usedGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue
        xmppList = []
        i        = 3
        os.system('clear')
        while i <= (len(kb.split(' ')) - 1):
            member = kb.split(' ')[i]
            i += 1
            mbrFile = 'tx.' + member + '.e'
            if (mbrFile in ['tx.local', 'rx.local']) or mbrFile not in entropyfilenames:
                print '\nError: Contact \'' + member + '\' was not accepted to group ' + usedGroup + '\n'
                continue
            xmppList.append(member)
        add_to_groupList(usedGroup, xmppList)
        continue


    # Remove member from group
    if kb.startswith('/group rm '):
        usedGroup = kb.split(' ')[2]
        if not usedGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue
        rmList = []
        i      = 3
        while i <= (len(kb.split(' ')) - 1):
            member = kb.split(' ')[i]
            i += 1
            rmList.append(member)
        os.system('clear')

        rem_from_groupList(usedGroup, rmList)
        print ''
        continue


    # Select group
    if kb.startswith('/group '):
        groupName = kb.split(' ')[1]
        if not groupName in groupFileList:
            print '\nError: Invalid group\n'
            groupName = ''
            continue
        else:
            nick = groupName
            os.system('clear')
            print 'Now sending messages to ' + nick + '\n'
            continue



    ##################################################################
    #                      OTHER LOCAL COMMANDS                      #
    ##################################################################

    if emergencyExit:
        if (kb == '  '):
            quitProcess(False)


    if (kb == '  ' or kb == '/clear'):
        os.system('clear')
        if localTesting:
            with open('TxOutput', 'w+') as txout:
                txout.write('clearScreen ' + xmpp + '\n')
                if debugging:
                    print 'Writing command \'clearScreen ' + xmpp + ' to file \'TxOutput\''
            continue

        else:
            port.write('clearScreen ' + xmpp + '\n')
            if debugging:
                print 'Sending command \'clearScreen ' + xmpp + '\' to NH'
            continue


    if (kb == '/quit' or kb == '/exit'):
        quitProcess(True)


    if (kb == ''):
        continue


    if (kb == '/help'):
        os.system('clear')
        print_help()
        continue


    if (kb == '/paste'):
        pastemode = True
        continue


    if (kb == '/about'):
        os.system('clear')
        print ' Tinfoil Chat ' + version + '\n'
        print ' https://github.com/maqp/tfc\n'
        print ' cs.helsinki.fi/u/oottela/TFC.pdf'
        print '                         /TFC-manual.pdf\n\n'
        continue


    if (kb == '/names'):
        os.system('clear')
        print ''
        print_list_of_contacts()
        print ''
        continue


    if kb.startswith('/msg '):
        try:
            selection     = kb.split(' ')[1]
            if selection in groupFileList:
                groupName = nick = selection
                os.system('clear')
                print 'Now sending messages to ' + nick + '\n'
                continue

            if selection in contacts:
                if (selection != 'local'):
                    xmpp = 'tx.' + selection
                    nick = get_nick(xmpp)
                    os.system('clear')
                    print 'Now sending messages to ' + nick + ' (' + xmpp[3:] + ')'
                    continue

            else:
                try:
                    selection    = int(selection)
                    if selection > get_contact_quantity() or selection < 0:
                        print '\nError: Invalid contact selection\n'
                        continue
                    else:
                        try:
                            xmpp, nick, msgKeyID = select_contact(maxWidth, idSelDist, selection, False)
                        except ValueError:
                            continue
                except ValueError:
                    print '\nError: Invalid contact selection\n'
                    continue
                except IOError:
                    print '\nstdIOError, please try again\n'
                    continue

                os.system('clear')
                ps1  = 'Now sending messages to ' + nick
                ps2  = ' (' + xmpp[3:] + ')\n'
                ttyW = int(subprocess.check_output(['stty', 'size']).split()[1])
                if len(ps1 + ps2) <= ttyW:
                    print ps1 + ps2
                else:
                    print ps1 + '\n' + ps2

                continue
        except AttributeError:
            pass



    ##################################################################
    ##                      COMMANDS TO RX.py                       ##
    ##################################################################

    if kb.startswith('/nick ') or kb.startswith('/logging '):
        cmdMsg      = ''
        cmdLogging  = False
        cmdNick     = False

        if not local_e_available:
            print 'Error: tx.local.e was not found'
            continue


        if kb.startswith('/nick '):
            if nick in groupFileList:
                print '\nGroup is selected, no nick was changed\n'
                continue

            if (len(kb) < 7):
                print 'Error: Can\'t give empty nick'
                continue

            newNick = kb.split(' ')[1]
            if '=' in newNick or '/' in newNick:
                print '\nError: Nick can not contain reserved characters / or =\n'
                continue
            if (newNick == 'tx.local') or (newNick == 'rx.local'):
                print '\nError: Can\'t give reserved nick of local.e to contact\n'
                continue
            if (newNick in groupFileList):
                print '\nError: Nick is in use for group\n'
                continue

            write_nick(xmpp, newNick)
            nick    = get_nick(xmpp)

            os.system('clear')
            print 'Changed contact\'s nick to ' + nick
            cmdMsg  = xmpp + '/nick=' + nick

        if kb.startswith('/logging '):
            ok    = False
            value = str(kb.split(' ')[1])
            if value  == 'on':
                cmdMsg = 'logson'
                ok     = True
            if value  == 'off':
                cmdMsg = 'logsoff'
                ok     = True
            if not ok:
                print '\nError: Invalid command\n'
                continue



        ##############################################################
        #                        COMMAND PACKET                      #
        ##############################################################

        if not commandMessageProcess(cmdMsg):
            ctrlRemaining = False
        continue



    ##############################################################
    ##                     FILE TRANSMISSION                    ##
    ##############################################################

    usedCommand = False     # If we reach this point, we know a command was not used

    if kb.startswith('/file '):
        fname = kb.split(' ')[1]
        if nick in groupFileList:
            sendTarget = 'all members of group' + nick
        else:
            sendTarget = xmpp[3:]
        if raw_input('\nThis will send file \'' + fname + '\' to ' + sendTarget + '.\nAre you sure? Type upper case YES to continue: ') == 'YES':
            print ''
            subprocess.Popen('base64 ' + fname + ' > TFCtmpFile', shell=True).wait()

            with open('TFCtmpFile', 'r') as mFile:
                fileContent = mFile.readlines()
                fileMessage = ''
                for filePart in fileContent:
                    fileMessage = fileMessage + filePart

            kb = 'TFCFILE' + fileMessage
            subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u TFCtmpFile', shell=True).wait()
        else:
            print '\nFile sending aborted\n'
            continue



    if kb.startswith('/dhe'):
        os.system('clear')

        print '\nThis will initiate Diffie-Hellman key exchange to create ephemeral encryption key.'

        if (raw_input('This takes a moment for both participants.\n\nIf you have agreed with recipient to do so, type \'YES\' to continue: ') == 'YES'):
            dhe_process(xmpp)
            continue
        else:
            print 'DHE aborted..'
            time.sleep(0.4)
            os.system('clear')
            continue


    ##############################################################
    ##                      GROUP MESSAGING                     ##
    ##############################################################

    if nick in groupFileList:

        activeGroup = get_group_members(groupName)
        print ''
        for item in activeGroup:
            print 'Sending message to ' + item
            xmpp = 'tx.' + item

            if len(kb) > (PkgSize - 3):
                if not longMessageProcess(kb, xmpp):
                    continue
            else:
                if not shortMessageProcess(kb, xmpp):
                    continue
                sleep(0.1)
                print ''



    ##############################################################
    ##                 SINGLE RECIPIENT MESSAGING               ##
    ##############################################################

    else:

        if len(kb) > (PkgSize):

            if not longMessageProcess(kb, xmpp):
                continue

        else:
            if not shortMessageProcess(kb, xmpp):
                continue



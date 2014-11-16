#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import binascii
import csv
import datetime
import fileinput
import getopt
import hashlib
import imp
import io
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
Rx.py
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
#                           CONFIGURATION                            #
######################################################################

os.chdir(sys.path[0])

timeStampFmt            = '%Y-%m-%d//%H:%M:%S'
kfOWIterations          = 3
remoteLogChangeAllowed  = True
fileSavingAllowed       = False
logTamperingEvent       = True
logReplayedEvent        = True
showLongMsgWarning      = True
debugging               = False
logMessages             = False
injectionTesting        = False

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

def keccak_decrypt(ciphertext, HexKey):

    # CTR mode, no authentication

    # Convert hexadecimal key to binary data
    key        = binascii.unhexlify(HexKey)

    # Separate 256-bit nonce from ciphertext
    nonce2     = ciphertext[:32]
    enc        = ciphertext[32:]

    # Generate 512-bit IV
    iv         = (key + nonce2)

    # Sponge function takes 512-bit IV, squeezes out 256 bit keystream block #1
    step       = keccak256(iv)

    i          = 1
    keystream  = ''

    # For n-byte message, n/32 additional rounds is needed to generate proper length keystream
    while (i < (len(ciphertext) / 32) ):
        keystream += step
        step       = keccak256(step)
        i         += 1

    # Convert key from hex format to binary
    keystreamBIN   = binascii.unhexlify(keystream)

    # XOR keystream with plaintext to acquire ciphertext
    if len(enc) == len(keystreamBIN):
        plaintext      = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(enc, keystreamBIN))
    else:
        print 'Ciphertext - keystream length mismatch (Keccak). Exiting'
        exit()

    # Remove padding
    plaintext      = plaintext[:-ord(plaintext[-1:])]


    return plaintext

def keccakVarLen(hashInput):
    hexMsg       = stringtoHex(hashInput)
    hashfunction = Keccak()
    return hashfunction.Keccak(((8 * len(hashInput)), hexMsg), 1088, 512, 0, 256, 0)    # Verbose Keccak hash function presentation when checkKeyHashes is enabled



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

def salsa_20_decrypt(ciphertext, hexKey):

    # Separate nonce from ciphertext
    nonce      = ciphertext[:24]
    ct         = ciphertext[24:]

    # Convert uppercase hex to lowercase
    hexKey     = hexKey.lower()

    # Convert hexadecimal key to bitstring
    key        = binascii.unhexlify(hexKey)

    # XOR ciphertext with keystream to acquire plaintext
    plaintext  = XSalsa20_xor(ct, nonce, key)

    return plaintext



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

def twofish_decrypt(ciphertext, HexKey):

    # Separate nonce from ciphertext
    nonce           = ciphertext[:16]
    ciphertext      = ciphertext[16:]

    # Convert uppercase hex to lowercase
    HexKey          = HexKey.lower()

    # Convert hexadecimal key to binary data
    key             = binascii.unhexlify(HexKey)

    # n.o. keystream blocks equals the n.o. CT blocks
    ctArray         = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]

    counter         = 1
    keystream       = ""

    for block in ctArray:
        # Convert integer counter to unique 16-byte counter
        binrep      = str(bin(counter))[2:].zfill(128)
        ctr         = ''.join(chr(int(binrep[i:i+8], 2)) for i in xrange(0, len(binrep), 8))

        # XOR 128-bit nonce with 128-bit counter to change nonce-input of Twofish cipher
        iv          = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(ctr, nonce))

        # Initialize Twofish cipher with key
        E           = Twofish(key)

        # Encrypt unique IV with key
        keyBlock    = E.encrypt(iv)

        # Append new block to keystream
        keystream  += keyBlock

        # Iterate the counter of randomized CTR mode
        counter    += 1

    # XOR keystream with ciphertext to acquire plaintext
    plaintext = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(ciphertext, keystream))

    # Remove padding
    plaintext      = plaintext[:-ord(plaintext[-1:])]

    return plaintext



######################################################################
#     AES (GCM) AUTHENTICATED ENCRYPTION (RIJNDAEL BLOCK CIPHER)     #
######################################################################

def AES_GCM_decrypt(ctInput, hexKey):

    nonce             = ctInput[:64]
    ciphertext        = ctInput[64:-16]
    mac               = ctInput[-16:]

    AESkey            = binascii.unhexlify(hexKey)
    cipher            = AES.new(AESkey, AES.MODE_GCM, nonce)
    cipher.update('')

    plaintext         = cipher.decrypt(ciphertext)

    if debugging:
        print 'M(encrypt): Using following parameters:'
        print '  Nonce   (len =  ' + str(len(nonce) * 8) + ' bits): "' + nonce + '"'
        print '  AES-key (len = '  + str(len(key)   * 8) + ' bits): "' + key   + '"'
        print '  Plaintext: "'     + plaintext                                 + '"'

    try:
        cipher.verify(mac)
        return plaintext
    except ValueError:
        print "WARNING! MAC verification failed! This might mean someone is tampering your messages!\n"
        return None
    except TypeError:
        print "WARNING! MAC verification failed! This might mean someone is tampering your messages!\n"
        return None

######################################################################
#                      DIFFIE-HELLMAN KEY EXCHANGE                   #
######################################################################

class DiffieHellman(object):

    prime       = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
    generator   = 2

    def __init__(self, privateKey):
        self.privateKey = privateKey
        self.publicKey  = ""



    def checkPublicKey(self, otherKey):
        if (otherKey > 2 and otherKey < self.prime - 1):

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


def dhe_process(xmpp):

    # Load local public DH key
    with open('dhe_me_' + xmpp[3:], 'r') as rFile:
        mePubKey = rFile.readline()

    # Load contact's public DH key
    with open('dhe_rx_' + xmpp[3:], 'r') as rFile:
        publicKey = rFile.readline()

    # Shred public DH key tmp storage
    subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u dhe_me_' + xmpp[3:], shell=True).wait()
    subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u dhe_rx_' + xmpp[3:], shell=True).wait()

    os.system('clear')
    print '\nDiffie-Hellman key-exchange with contact ' + xmpp[3:] + ' initiated. Please follow the instructions'

    # User entry of private DH key
    c = 1
    sKey = ""
    while (c < 19):
        block = raw_input('\n1. Enter private key block '+ str(c) +': ')

        keyOfBlock   = block[:-3]
        crcFromBlock = block[-3:]
        crcOfBlock   = crc32(keyOfBlock)
        crcOfBlock   = crcOfBlock[-3:]

        while (crcFromBlock != crcOfBlock):
            block = raw_input('Typing error\n\n1. Enter private key block '+ str(c) +': ')

            keyOfBlock   = block[:-3]
            crcFromBlock = block[-3:]
            crcOfBlock   = crc32(keyOfBlock)
            crcOfBlock   = crcOfBlock[-3:]

        sKey = sKey + keyOfBlock
        c += 1


    # Generate shared secret key
    a   = DiffieHellman(int(sKey))
    a.genKey(int(publicKey))
    ssk = str(binascii.hexlify(a.key))

    os.system('clear')
    print     '\n3. Shared Secret Key for  TxM: ' + ssk
    print     '\n4. CRC32 of Shared Secret Key: ' + crc32(ssk)
    raw_input('\nPress enter when ready')

    # Input secret to salt hash of DH shared secret key
    os.system('clear')
    print '5. Since we are assuming adversary is already in control of all deterministic keys\ncurrently in use, hash of public key needs to be verified manually. Call your contact\nand on the phone, agree on a secret that is hard for adversary to guess.'
    print '\n                         DO NOT SAY THE SECRET ALOUD!'

    salt     = raw_input('\n6. Enter the secret, that was agreed on: ')
    pKeyHash = keccakVarLen(salt + ssk)
    hashSpc  = ' '.join(pKeyHash[i:i+8] for i in xrange(0,len(pKeyHash),8))

    print '\n7. Read the following hash taking turns on each block.'
    print '\n   ' + hashSpc

    # Generate session keys to decrypt outgoing and incoming messages
    ssk2 = keccakVarLen(ssk + publicKey[:20])
    ssk3 = keccakVarLen(ssk + mePubKey[:20])

    success = ""
    while (success != 'VERIFIED') and (success != 'MISMATCH'):
        success = raw_input('\nIf the hash was a match, type  \'VERIFIED\' , else type \'MISMATCH\': ')
    if (success == 'MISMATCH'):
        os.system('clear')
        print 'DHE aborted. Continuing with old keys'
        pass
    if (success == 'VERIFIED'):
        DH_Write_Key(xmpp, ssk2, ssk3)
        os.system('clear')
        print 'DHE finished succesfully'

def dhe_write_me(xmpp, key):
    with open('dhe_me_' + xmpp[3:], 'w+') as iFile:
        iFile.write(key[10:])

def dhe_write_rx(xmpp, key):
    with open('dhe_rx_' + xmpp[3:], 'w+') as iFile:
        iFile.write(key[10:])

def DH_Write_Key(xmpp, ssk2, ssk3):

    with open('rx.' + xmpp[3:] + '.e', 'r') as efile:
        keys1 = efile.readlines()

    keys1[3] = ssk2
    with open('rx.' + xmpp[3:] + '.e', 'w+') as efile:
        for key in keys1:
            efile.write(key)


    with open('me.' + xmpp[3:] + '.e', 'r') as efile:
        keys2 = efile.readlines()

    keys2[3] = ssk3
    with open('me.' + xmpp[3:] + '.e', 'w+') as efile:
        for key in keys2:
            efile.write(key)



######################################################################
#                        KEY MANAGEMENT FUNCTIONS                    #
######################################################################

def store_keyID(xmpp, keyID):
    contacts = []
    with open('rxc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)

    for i in range( len(contacts) ):
        if contacts[i][1] == xmpp:
           contacts[i][2] = keyID

    with open('rxc.tfc', 'w') as cFile:
        writer = csv.writer(cFile)
        writer.writerows(contacts)

    if debugging:
        print '\nM(store_keyID): Wrote line \'' + str(keyID) + '\' for contact ' + xmpp + ' to txc.tfc\n'



def get_keyID(xmpp):
    contacts = []
    with open('rxc.tfc', 'r') as cFile:
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



def rotate_keyset(xmpp, keySet):
    with open(xmpp + '.e', 'w+') as efile:
        for key in keySet:
            nKey = keccak256(key)
            efile.write(nKey + '\n')



def decrypt(xmpp, ct4, keyID):

    storedKeyID  = int(get_keyID(xmpp))
    contactKeyID = int(keyID)
    keyAdv       = contactKeyID - storedKeyID
    keySet       = get_xmpp_keyset(xmpp)

    if (keyAdv > 0):
        if (xmpp == 'rx.local'):
            print '\nATTENTION! It appears the last ' + str(keyAdv) + ' commands have not been received from TxM.\n'
        else:
            print '\nATTENTION! It appears the last ' + str(keyAdv) + ' messages have not been received from ' + xmpp[3:] + '.\n'


    # Iterate keyset through keccak until it matches contact's keyset iteration number
    i = 0
    if (i < keyAdv):
        while (i < keyAdv):
            n = 0
            while (n < 4):
                keySet[n] = keccak256(keySet[n])
                n += 1
            i+=1

    ct3 = AES_GCM_decrypt  (ct4, keySet[3])
    ct2 = twofish_decrypt  (ct3, keySet[2])
    ct1 = salsa_20_decrypt (ct2, keySet[1])
    pt  = keccak_decrypt   (ct1, keySet[0])

    # Store next keyset
    rotate_keyset(xmpp, keySet)

    # Store keyID
    store_keyID(xmpp, contactKeyID + 1)

    return pt



######################################################################
#                             SETTERS                                #
######################################################################

def addContact(nick, xmpp):
    contacts = []
    with open('rxc.tfc', 'a+') as cFile:
        datareader = csv.reader(cFile)
        for row in datareader:
            contacts.append(row)
        cFile.write(nick + ',' + xmpp + ',1\n')
    if debugging:
        print '\nM(add_contact):\nAdded contact ' + nick + ' (xmpp = ' + xmpp + ') to txc.tfc\n'



def search_new_contacts():
    contacts    = []
    datareader  = csv.reader(open('rxc.tfc', 'a+'))
    for row in datareader:
        contacts.append(row)

    for item in entropyfilenames:
        onList  = False
        xmpp    = item[:-2]

        for person in contacts:
            if xmpp in person[1]:
                onList = True
        if not onList:

            if (xmpp == 'tx.local'):
                continue

            if (xmpp == 'rx.local'):
                addContact('rx.local', 'rx.local')
                continue

            if xmpp.startswith('me.'):
                localNick = xmpp.split('@')[0][3:]
                addContact('me.' + localNick, xmpp)
                continue

            if xmpp.startswith('rx.'):
                newNick = raw_input('New contact ' + xmpp + ' found. Enter nickname: ')
                addContact(newNick, xmpp)



def write_nick(xmpp, nick):
    contacts = []
    with open ('rxc.tfc', 'r') as cFile:
        datareader = csv.reader(cFile)

        for row in datareader:
            contacts.append(row)
        for i in range( len(contacts) ):
            if  contacts[i][1] == xmpp:
                contacts[i][0] = nick

    with open('rxc.tfc', 'w') as cFile:
        writer = csv.writer(cFile)
        writer.writerows(contacts)

    if debugging:
        print '\nM(write_nick):\nWrote nick = ' + nick + ' for contact ' + xmpp + ' to rxc.tfc\n'



def writeLog(nick, xmpp, message):
    message = message.strip('\n')

    with open('logs.' + xmpp + '.tfc', 'a+') as lFile:
        lFile.write(datetime.datetime.now().strftime(timeStampFmt) + ' ' + nick + ': ' + message + '\n')

    if debugging:
        print '\nM(writeLog):\nAdded log entry \'' + message + '\' for contact ' + xmpp + ' (nick=' + nick + ')\n'



######################################################################
#                             GETTERS                                #
######################################################################

def get_nick(xmpp):
    contacts = []
    with open('rxc.tfc', 'r') as cFile:
        csvData = csv.reader(cFile)
        for row in csvData:
            contacts.append(row)
        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                nick = contacts[i][0]
        if debugging:
            print '\nM(get_nick): Loaded nick ' + nick + ' for contact ' + xmpp + '\n'
        return nick



def get_entropy_file_list():
    entropyfilenames = []
    for item in os.listdir('.'):
        if item.endswith('.e'):
            if not item.startswith('tx.'):
                entropyfilenames.append(item)
    return entropyfilenames



def search_contact_keyfiles():
    keyfiles  = []
    keyfiles += [each for each in os.listdir('.') if each.endswith('.e')]
    if not keyfiles:
        print '\nError: No keyfiles for contacts were found. Make sure they are in same directory as Rx.py\n'
        exit()



######################################################################
#                            WARNINGS                                #
######################################################################

def opsecWarning():
    print '''
REMEMBER! DO NOT MOVE RECEIVED FILES FROM RxM TO LESS SECURE
ENVIRONMENTS INCLUDING UNENCRYPTED SYSTEMS, ONES IN PUBLIC USE,
OR TO ANY SYSTEM THAT HAS NETWORK-CAPABILITY, OR THAT MOVES
FILES TO COMPUTER WITH NETWORK CAPABILITY.

DOING SO WILL RENDER DATA-DIODE PROTECTION USELESS, AS MALWARE
\'STUCK IN RXM\' CAN EASILY EXFILTRATE KEYS AND/OR PLAINTEXT
THROUGH THIS RETURN CHANNEL!

IF YOU NEED TO RETRANSFER A DOCUMENT, EITHER READ IT FROM RXM SCREEN
USING OPTICAL-CHARACTER RECOGNITION (OCR) SOFTWARE RUNNING ON TXM,
OR USE A PRINTER TO EXPORT THE DOCUMENT, AND A SCANNER TO READ IT TO
TXM FOR ENCRYPTED RETRANSFER. REMEMBER TO DESTROY THE PRINTS, AND IF
YOUR LIFE DEPENDS ON IT, THE PRINTER AND SCANNER ASWELL.\n'''



######################################################################
#                         MSG PROCESSING                             #
######################################################################

def b64d(content):
    return base64.b64decode(content)



def crc32(content):
    return str(hex(zlib.crc32(content)))



######################################################################
#                           LOCAL TESTING                            #
######################################################################

def clearLocalMsg():
    if localTesting:
        if injectionTesting:
            open('INoutput', 'w+').close()
        open('NHoutput', 'w+').close()



def loadMsg():
    if injectionTesting:
        with open('INoutput', 'r') as mFile:
            loadMsg = mFile.readline()
            if debugging:
                if not (loadMsg==''):
                    print '\n\nM(loadMSG): Loaded following message \n' + loadMsg
        return loadMsg

    else:
        with open('NHoutput', 'r') as mFile:
                loadMsg = mFile.readline()
                if debugging:
                    if not (loadMsg==''):
                        print '\n\nM(loadMSG): Loaded following message \n' + loadMsg
        return loadMsg



######################################################################
#                             PRE LOOP                               #
######################################################################

longMsgComplete  = False
fileReceive      = False
dhe_me           = False
dhe_rx           = False

entropyfilenames = get_entropy_file_list()
longMsg          = {}
longMessage      = ''

search_new_contacts()
search_contact_keyfiles()
clearLocalMsg()

os.system('clear')
print 'Rx.py Running'

if logMessages:
    print 'Logging is currently enabled'
else:
    print 'Logging is currently disabled'



######################################################################
#                               LOOP                                 #
######################################################################

try:
    while True:
        sleep(0.01)
        receivedpkg  = ''
        fileReceived = False

        if localTesting:
            try:
                receivedpkg  = loadMsg()
                if not receivedpkg.endswith('\n'):
                    continue
            except IOError:
                continue
        else:
            receivedpkg      = port.readline()

        clearLocalMsg()

        if not (receivedpkg == ''):
            try:

                if receivedpkg.startswith('exitTFC'):
                    os.system('clear')
                    exit()
                    continue

                if receivedpkg.startswith('clearScreen'):
                    os.system('clear')
                    continue



                ##############################################################
                #                     CONTROL MESSAGE                        #
                ##############################################################

                if receivedpkg.startswith('<ctrl>'):
                    cmdMACln, crcPkg = receivedpkg[6:].split('~')
                    crcPkg           = crcPkg.strip('\n')
                    xmpp             = 'rx.local'

                    # Check that CRC32 Matches
                    if (crc32(cmdMACln) == crcPkg):
                        payload, keyID     = cmdMACln.split('|')
                        ciphertext         = b64d(payload)


                        # Check that keyID is fresh
                        storedKey = int(get_keyID('rx.local'))
                        if (int(keyID) < storedKey):
                            print + '\nWARNING! Expired key detected!\nIt is possible someone is trying to replay commands!\n'
                            if logReplayedEvent:
                                writeLog('', '', 'EVENT WARNING: Replayed command received!')
                            continue


                        try:
                            # Decrypt command if MAC verification succeeds
                            decryptedMsg         = decrypt(xmpp, ciphertext, keyID)
                        except ValueError:
                                if logTamperingEvent:
                                    writeLog('','', 'EVENT WARNING: Tampered/malformed command received!')
                                continue
                        except TypeError:
                                if logTamperingEvent:
                                    writeLog('','', 'EVENT WARNING: Tampered/malformed command received!')
                                continue


                        # Remove padding
                        while decryptedMsg.endswith(' '):
                            decryptedMsg     = decryptedMsg[:-1]

                        ##################
                        # Enable logging #
                        ##################
                        if decryptedMsg.startswith('logson'):
                            if remoteLogChangeAllowed:
                                if logMessages:
                                    print 'Logging is already enabled'
                                else:
                                    logMessages = True
                                    print 'Logging has been enabled'
                                continue
                            else:
                                print '\nLogging settings can not be altered: Boolean value \'remoteLogChangeAllowed\' is currently set to False in Rx.py'
                                continue


                        ###################
                        # Disable logging #
                        ###################
                        if decryptedMsg.startswith('logsoff'):
                            if remoteLogChangeAllowed:
                                if not logMessages:
                                    print 'Logging is already disabled'
                                    continue
                                else:
                                    logMessages = False
                                    print 'Logging has been disabled'
                                    continue
                            else:
                                print '\nLogging settings can not be altered: Boolean value \'remoteLogChangeAllowed\' is currently set to False in Rx.py'
                                continue

                        ###############
                        # Change nick #
                        ###############

                        xmpp, cmdWp    = decryptedMsg.split('/')
                        cmd, parameter = cmdWp.split('=')

                        if cmd.startswith('nick'):

                            # Write and load nick
                            xmpp       = 'r' + xmpp[1:]
                            write_nick(xmpp, parameter)
                            rxNick     = get_nick(xmpp)
                            print '\nChanged ' + xmpp[3:] + ' nick to \'' + rxNick + '\'\n'
                            continue

                    else:
                        print '\nCRC checksum error: Command received by RxM was malformed.\nRequest the message again from your contact'
                        print 'If this error is persistent, check the batteries of your RxM data diode.\n'



                ##############################################################
                #                     NORMAL MESSAGE                         #
                ##############################################################
                if receivedpkg.startswith('<mesg>'):
                    xmpp, ctMACln, crcPkg = receivedpkg[6:].split('~')
                    crcPkg = crcPkg.strip('\n')



                    # Check that CRC32 Matches
                    if (crc32(ctMACln) == crcPkg):
                        encodedMsgMAC, keyID = ctMACln.split('|')
                        ciphertext           = b64d(encodedMsgMAC)


                        # Check that keyID is fresh
                        storedKey = int(get_keyID(xmpp))
                        if  (int(keyID) < storedKey):
                            print '\nWARNING! Expired key detected!\nIt is possible someone is trying to replay messages!\n'
                            if logReplayedEvent:
                                writeLog('', xmpp, 'EVENT WARNING: Possibly replayed message received!')
                            continue


                        try:
                            # Decrypt message if MAC verification succeeds
                            decryptedMsg     = decrypt(xmpp, ciphertext, keyID)
                        except ValueError:
                                if logTamperingEvent:
                                    writeLog('',xmpp, 'EVENT WARNING: Tampered/malformed message received!')
                                continue
                        except TypeError:
                                if logTamperingEvent:
                                    writeLog('',xmpp, 'EVENT WARNING: Tampered/malformed message received!')
                                continue

                        # Remove whitespace around message
                        while decryptedMsg.endswith(' '):
                            decryptedMsg = decryptedMsg[:-1]
                        while decryptedMsg.startswith(' '):
                            decryptedMsg = decryptedMsg[1:]


                        if decryptedMsg.startswith('s'):

                            ###################################
                            # Process short standard messages #
                            ###################################

                            if decryptedMsg.startswith('sTFCFILE'):
                                if fileSavingAllowed:
                                    print 'Receiving file, this make take a while. Notice that you can\'t\nreceive messages until you have received and named the file!'
                                    fileReceive  = True
                                    fileReceived = True
                            decryptedMsg = decryptedMsg[1:]

                        else:

                            ############################################
                            # Process long messages and file transfers #
                            ############################################

                            # Start packet of long message / file
                            if decryptedMsg.startswith('l'):
                                if decryptedMsg.startswith('lTFCFILE'):
                                    if fileSavingAllowed:
                                        print 'Receiving file, this make take a while. Notice that you can\'t\nreceive messages until you have received and named the file'
                                        fileReceive = True
                                else:
                                    if showLongMsgWarning:
                                        print '\n' + 'Receiving long message, please wait...\n'
                                longMsg[xmpp]    = decryptedMsg[1:]
                                continue


                            # Append packet of long message / file
                            if decryptedMsg.startswith('a'):
                                longMsg[xmpp]    = longMsg[xmpp] + decryptedMsg[1:]
                                continue


                            # End packet of long message / file
                            if decryptedMsg.startswith('e'):
                                longMsg[xmpp]    = longMsg[xmpp] + decryptedMsg[1:]
                                decryptedMsg     = longMsg[xmpp] + '\n'
                                if fileReceive:
                                    fileReceived = True


                        if not fileReceive:

                            ##############################
                            # Process printable messages #
                            ##############################

                            if xmpp.startswith('me.'):
                                nick = 'Me > '   + get_nick('rx' + xmpp[2:])
                            else:
                                nick = 5   * ' ' + get_nick(xmpp)

                            ###############################
                            # Diffie-hellman Key-exchange #
                            ###############################

                            if decryptedMsg.startswith('DH_PUBKEY_'):
                                if nick.startswith('Me > '):
                                    dhe_write_me(xmpp, decryptedMsg)
                                    dhe_me = True

                                else:
                                    dhe_write_rx(xmpp, decryptedMsg)
                                    dhe_rx = True

                                if  (dhe_rx and dhe_me):
                                    dhe_me = False
                                    dhe_rx = False
                                    dhe_process(xmpp)
                                    decryptedMsg = ''
                                    continue

                                else:
                                    if dhe_me:
                                        print 'Waiting for ' + xmpp[3:] + '\'s DHE public key'
                                        continue
                                    if dhe_rx:
                                        print 'Your contact ' + xmpp[3:] + ' has initated DHE. Please select your contact and type command \'/dhe\''
                                        continue

                            # Print message to user
                            print nick + ':    ' + decryptedMsg


                            # Log messages if logging is enabled
                            if logMessages:
                                if nick.startswith('Me > '):
                                    spacing = len(get_nick('rx' + xmpp[2:]))
                                    nick    = (spacing - 2) * ' ' + 'Me'
                                    writeLog(nick, xmpp[3:], decryptedMsg)
                                else:
                                    writeLog(nick[5:], xmpp[3:], decryptedMsg)


                        if fileReceive:

                            ##########################
                            # Process received files #
                            ##########################

                            if fileSavingAllowed:
                                if fileReceived:

                                    fName = raw_input('\nFile Received. Enter filename (\'r\' rejects file): ')

                                    # File rejection option
                                    if fName == 'r':
                                        print '\nFile Rejected. Continuing\n'
                                        decryptedMsg == ''
                                        fileReceive  = False
                                        fileReceived = False
                                        continue

                                    # Save received base64 data to tmp file and decode it to user-specified file. Shred tmp file. and show OPSEC warning.
                                    else:
                                        with open('TFCtmpFileRx', 'w+') as mFile:
                                            mFile.write(decryptedMsg[7:])
                                        subprocess.Popen('base64 -d TFCtmpFileRx > ' + fName, shell=True).wait()
                                        subprocess.Popen('shred -n ' + str(kfOWIterations) + ' -z -u TFCtmpFileRx', shell=True).wait()
                                        fileReceive  = False
                                        fileReceived = False

                                        opsecWarning()
                                else:
                                    continue
                            else:
                                decryptedMsg == ''
                                continue
                        continue




                    else:
                        print '\nCRC checksum error: Message received by RxM was malformed.\n'
                        print 'Note that this error occured between your NH and RxM so recipient most likely received the message.'
                        print 'If this error is persistent, check the batteries of your RxM data diode.\n'


            except IndexError:
                print 'WARNING! Received message/command wasn\'t correctly formatted. This might indicate someone is tampering messages!'
                continue
            except ValueError:
                print 'WARNING! Received message/command wasn\'t correctly formatted. This might indicate someone is tampering messages!'
                continue

except KeyboardInterrupt:
    os.system('clear')
    print 'Exiting Rx.py\n'
    exit()


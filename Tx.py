#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import csv
import math
import os
import random
import readline
import serial
import subprocess
import sys
import time
from time import sleep



######################################################################
#                             LICENCE                                #
######################################################################

# TFC-CEV (Cascading Encryption Version) || Tx.py
version = 'CEV 0.4.12 beta'

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
"""



######################################################################
#                            CONFIGURATION                           #
######################################################################

PkgSize            = 140
maxSleepTime       = 13
shredIterations    = 3
lMsgSleep          = 0.2

debugging          = False
emergencyExit      = False
randomSleep        = False
localTesting       = False

if not localTesting:
    port = serial.Serial('/dev/ttyAMA0', baudrate=9600, timeout=0.1)



######################################################################
#                          KECCAK STREAM CIPHER                      #
######################################################################

"""
Algorithm Name: Keccak

Authors: Guido Bertoni, Joan Daemen, Michael Peeters and Gilles
Van Assche Implementation by Renaud Bauvin, STMicroelectronics

This code, originally by Renaud Bauvin, is hereby put in the public
domain. It is given as is, without any guarantee.

For more information, feedback or questions, please refer to our
website: http://keccak.noekeon.org/
"""



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



def keccak_256(hashInput):
    hexMsg = binascii.hexlify(hashInput)
    return Keccak().Keccak(((8 * len(hashInput)), hexMsg), 1088, 512, 0, 256, 0)



def keccak_encrypt(message, HexKey):

    #CTR mode, no authentication.

    # Add padding to plainText, (256-bit block-size).
    length    = 32 - (len(message) % 32)
    message  += length * chr(length)

    # Convert hexadecimal key to binary data.
    key       = binascii.unhexlify(HexKey)

    # Generate 256-bit nonce.
    nonce     = os.urandom(32)

    # Generate 512-bit IV.
    iv        = (key + nonce)

    # Sponge function takes 512-bit IV, squeezes out 256 bit keystream block #1.
    step      = keccak_256(iv)

    i         = 0
    keystream = ''

    # For n-byte message, n/32 additional rounds is needed to generate proper length keystream.
    while i < (len(message) / 32):
        keystream += step
        step       = keccak_256(key + step)
        i         += 1

    # Convert key from hex format to binary data.
    keystreamBIN = binascii.unhexlify(keystream)

    # XOR keystream with plaintext to acquire ciphertext.
    if len(message) == len(keystreamBIN):
        ciphertext = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(message, keystreamBIN))
    else:
        os.system('clear')
        print '\nCRITICAL ERROR! Keccak ciphertext - keystream length mismatch. Exiting.\n'
        exit()

    return nonce + ciphertext



######################################################################
#                        SALSA20 STREAM CIPHER                       #
######################################################################

"""
This file is part of Python Salsa20
a Python bridge to the libsodium C [X]Salsa20 library
Released under The BSD 3-Clause License

Copyright (c) 2013 Keybase
Python module and ctypes bindings
"""

import imp
from ctypes import (cdll, c_char_p, c_int, c_uint64, create_string_buffer)
from ctypes import (cdll, Structure, POINTER, pointer, c_char_p, c_int, c_uint32, create_string_buffer)


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

    # Convert hexadecimal key to bitstring.
    key        = binascii.unhexlify(hexKey)

    # Generate unique nonce.
    nonce      = os.urandom(24)

    # XOR plaintext with keystream to acquire ciphertext.
    ciphertext = XSalsa20_xor(plaintext, nonce, key)

    return nonce + ciphertext



######################################################################
#                        TWOFISH BLOCK CIPHER                        #
######################################################################

"""
This file is part of Python Twofish a Python bridge to the C Twofish library by Niels Ferguson
Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase
Python module and ctypes bindings
"""

import imp

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
        if not len(key) > 0 and len(key) <= 32:
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



def self_test():
    # Repeat the test on the same vectors checked at runtime by the library
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
            exit_with_msg('CRITICAL ERROR! Twofish library is corrupted')

# Perform Twofish library self-test.
self_test()



def twofish_encrypt(plainText, HexKey):

    #CTR mode, no authentication.

    # Add padding to plainText.
    length     = 16 - (len(plainText) % 16)
    plainText += length * chr(length)

    # Convert hexadecimal key to binary data.
    key        = binascii.unhexlify(HexKey)

    # Generate 128-bit nonce.
    nonce      = os.urandom(16)

    # n.o. keystream blocks equals the n.o. CT blocks.
    msgA       = [plainText[i:i + 16] for i in range(0, len(plainText), 16)]

    keystream  = ''
    counter    = 1

    for block in msgA:

        # Hash the counter value and output 64 hex numbers.
        counterHash = keccak_256(str(counter))

        # Convert the digest to 32-bit binary.
        counterBin  = binascii.unhexlify(counterHash)

        # Truncate length to 128 bits.
        ctr         = counterBin[:16]

        # XOR 128-bit nonce with 128-bit hash of counter to create IV of Twofish cipher.
        if len(ctr) == 16 and len(nonce) == 16:
            iv       = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(ctr, nonce))
        else:
            exit_with_msg('CRITICAL ERROR! Twofish counter hash - nonce length mismatch.')

        # Initialize Twofish cipher with key.
        E           = Twofish(key)

        # Encrypt unique IV with key.
        keyBlock    = E.encrypt(iv)

        # Append new block to keystream.
        keystream  += keyBlock

        # Increase the counter of randomized CTR mode.
        counter    += 1

    # XOR keystream with plaintext to acquire ciphertext.
    if len(plainText) == len(keystream):
        ciphertext = ''.join(chr(ord(msgLetter) ^ ord(keyLetter)) for msgLetter, keyLetter in zip(plainText, keystream))
    else:
        print '\nCRITICAL ERROR! Twofish plaintext - keystream length mismatch. Exiting.'
        exit()

    return nonce + ciphertext



######################################################################
#     AES (GCM) AUTHENTICATED ENCRYPTION (RIJNDAEL BLOCK CIPHER)     #
######################################################################

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
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

try:
    import Crypto.Random.random
    secure_random = Crypto.Random.random.getrandbits

except ImportError:
    import OpenSSL
    print 'WARNING Failed to import Crypto.Random, trying OpenSSL instead.'
    secure_random = lambda x: long(hexlify(OpenSSL.rand.bytes(x>>3)), 16)



def write_nonce(nonce):
    with open('usedNonces.tfc', 'a+') as file:
        file.write( b64e(nonce) + '\n' )



def nonce_is_blacklisted(nonce):
    b64Nonce = b64e(nonce)
    try:
        with open('usedNonces.tfc', 'r') as file:
            for line in file:
                if b64Nonce in line:
                    return True
            return False

    except IOError:
        return False



def AES_GCM_encrypt(plaintext, hexKey):

    # Convert hex key to binary format.
    AESkey     = binascii.unhexlify(hexKey)

    # Generate 512 bit nonce.
    nonce      = get_random_bytes(64)

    # Verify that nonce has not been used before.
    while nonce_is_blacklisted(nonce):
        nonce  = get_random_bytes(64)

    # Write nonce value.
    write_nonce(nonce)

    # Initialize cipher.
    cipher     = AES.new(AESkey, AES.MODE_GCM, nonce)
    cipher.update('')

    ctArray    = nonce, cipher.encrypt(plaintext), cipher.digest()
    ciphertext = ''

    # Convert ciphertext array to string.
    for i in ctArray:
        ciphertext += i

    return ciphertext



######################################################################
#                    ENCRYPTION AND KEY MANAGEMENT                   #
######################################################################

def get_keyset(xmpp, output=True):
    try:
        keySet = []

        with open(xmpp + '.e', 'r') as file:
            keyFile = file.readlines()

        for line in keyFile:
            key = line.strip('\n')

            # Verify keys in keyfile have proper hex-format.
            validChars = ['0','1','2','3','4','5','6','7','8','9','A',
                          'B','C','D','E','F','a','b','c','d','e','f']

            for char in key:
                if not char in validChars:
                    exit_with_msg('CRITICAL ERROR! Illegal char \'' + str(char) + '\' in keyfile\n' + xmpp + '.e.')


            # Verify keys are of proper length.
            if len(key) != 64:
                exit_with_msg('CRITICAL ERROR! Illegal length key in keyfile\n' + xmpp + '.e. Exiting.')
            else:
                keySet.append(key)

        # Verify that four keys were loaded.
        if len(keySet) != 4:
            exit_with_msg('CRITICAL ERROR! Keyfile ' + xmpp + '.e\nhas illegal number of keys.')

        # Verify that all keys are unique.
        if any(keySet.count(key) > 1 for key in keySet):
            exit_with_msg('CRITICAL ERROR! Two identical keys in keyfile\n' + xmpp + '.e.')

        if debugging and output:
            print '\nM(get_keyset): Loaded following set of keys for XMPP' + xmpp + '\n'
            for key in keySet:
                print key

        return keySet

    except IOError:
        exit_with_msg('CRITICAL ERROR! Failed to open keyfile for XMPP\n' + xmpp + '.')




def rotate_keyset(xmpp):
    try:

        keySet  = get_keyset(xmpp, False)

        newKeys = []
        with open(xmpp + '.e', 'w+') as file:
            for key in keySet:
                newKey = keccak_256(key)
                newKeys.append(newKey)
                file.write(newKey + '\n')

        if debugging:
            print '\nM(rotate_keyset): Wrote following keys for contact ' + xmpp + '\n'
            for key in newKeys:
                print key

        # Verify that keys were successfully written.
        storedKeySet = get_keyset(xmpp, False)

        if newKeys != storedKeySet:
            exit_with_msg('CRITICAL ERROR! Next keyset was not properly stored.')

        else:
            if debugging:
                print '\nM(rotate_keyset): Key overwriting successful.\n'

    except IOError:
        exit_with_msg('CRITICAL ERROR! Keyfile ' + xmpp + '.e\ncould not be loaded.')




def encrypt(xmpp, pt):

    keySet  = get_keyset(xmpp)

    ct1 = keccak_encrypt  (pt,  keySet[0])
    ct2 = salsa_20_encrypt(ct1, keySet[1])
    ct3 = twofish_encrypt (ct2, keySet[2])
    ct4 = AES_GCM_encrypt (ct3, keySet[3])

    rotate_keyset(xmpp)

    return ct4



######################################################################
#                        txc.tfc MANAGEMENT                          #
######################################################################

def add_contact(nick, xmpp):
    try:
        with open('txc.tfc', 'a+') as file:
                file.write(nick + ',' + xmpp + ',1\n')

        if debugging:
            print '\nM(add_contact): Added contact ' + nick + ' (xmpp = ' + xmpp + ') to txc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def write_nick(xmpp, nick):
    try:
        contacts = []

        with open ('txc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        nickChanged = False

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                contacts[i][0] = nick
                nickChanged = True

        if not nickChanged:
            exit_with_msg('ERROR! Could not find XMPP\n' + xmpp + ' from txc.tfc.')


        with open('txc.tfc', 'w') as file:
            writer = csv.writer(file)
            writer.writerows(contacts)

        if debugging:
            print '\nM(write_nick):\nWrote nick ' + nick + ' for account ' + xmpp + ' to txc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def get_nick(xmpp):
    try:
        contacts = []

        with open('txc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                nick = contacts[i][0]
                return nick

        exit_with_msg('ERROR! Failed to load nick for contact.')

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def write_keyID(xmpp, keyID):
    try:
        contacts = []

        with open('txc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        keyIDChanged = False

        for i in range(len(contacts)):
            if contacts[i][1] == xmpp:
                contacts[i][2] = keyID
                keyIDChanged   = True

        if not keyIDChanged:
            exit_with_msg('ERROR! Could not find ' + xmpp + ' from txc.tfc.')

        with open('txc.tfc', 'w') as file:
            writer = csv.writer(file)
            writer.writerows(contacts)

        # Verify keyID has been properly written.
        newStoredKey = get_keyID(xmpp)
        if keyID != newStoredKey:
            exit_with_msg('CRITICAL ERROR! KeyID was not properly stored.')


        if debugging:
            print '\nM(write_keyID): Wrote line \'' + str(keyID) + '\' for contact ' + xmpp + ' to txc.tfc\n'

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def get_keyID(xmpp):
    try:
        contacts = []

        with open('txc.tfc', 'r') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        for i in range( len(contacts) ):
            if contacts[i][1] == xmpp:
                keyID = int(contacts[i][2])

        # Verify keyID is positive.
        if keyID > 0:
            return keyID
        else:
            exit_with_msg('ERROR! Failed to load valid keyID for ' + xmpp + '.')

    except ValueError:
        exit_with_msg('ERROR! Failed to load valid keyID for ' + xmpp + '.')

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded. Exiting.')



def add_keyfiles(keyFileNames):
    try:
        contacts = []

        with open('txc.tfc', 'a+') as file:
            csvData = csv.reader(file)

            for row in csvData:
                contacts.append(row)

        for fileName in keyFileNames:
            onList = False
            xmpp   = fileName[:-2]

            for user in contacts:
                if xmpp in user[1]:
                    onList = True

            if not onList:

                if xmpp == 'tx.local':
                    add_contact('tx.local', 'tx.local')

                else:
                    os.system('clear')
                    print 'TFC ' + version + ' || Tx.py' + '\n'
                    newNick = raw_input('New contact ' + xmpp[3:] + ' found. Enter nick: ')
                    add_contact(newNick, xmpp)

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



######################################################################
#                             GETTERS                                #
######################################################################

def get_keyfile_list():
    keyFileList     = []
    xmppAddressList = []

    for file in os.listdir('.'):
        if file.endswith('.e'):
            if not file.startswith('me.') and not file.startswith('rx.'):
                keyFileList.append(file)
                xmppAddressList.append(file[3:][:-2])
    return keyFileList, xmppAddressList



def get_contact_quantity():
    try:
        with open('txc.tfc', 'r') as file:
            for i, l in enumerate(file):
                pass

            for line in file:
                    if 'tx.local' in line:
                        return i
        return i + 1

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')



def get_autotabs(contacts):

    autoTabs = []

    # Add contacts to autoTabs.
    for contact in contacts:
        autoTabs.append(contact + ' ')

    # Add group names to autoTabs.
    gFileList = get_group_list(False)
    for gFile in gFileList:
        autoTabs.append(gFile + ' ')

    # Add commands to autoTabs.
    cList = ['about' , 'add '  , 'clear', 'create ' , 'exit',
             'file ' , 'group ', 'help' , 'logging ', 'msg ',
             'newkf ', 'nick ' , 'quit' , 'rm '     , 'select ']

    for command in cList:
        autoTabs.append(command)

    return autoTabs



def get_terminal_width():
    return int(subprocess.check_output(['stty', 'size']).split()[1])



######################################################################
#                        CHECKS AND WARNINGS                         #
######################################################################

def search_keyfiles():
    keyfiles  = []
    keyfiles += [file for file in os.listdir('.') if file.endswith('.e')]
    if not keyfiles:
        exit_with_msg('Error: No keyfiles for contacts were found.\n'
                      'Make sure keyfiles are in same directory as Tx.py.')



def chk_pkgSize():
    if PkgSize > 250:
        exit_with_msg('ERROR! Maximum length of packet is 250 characters.\n' \
              'Please fix the value \'PkgSize\'and restart TFC.')


    if PkgSize < 25:
        exit_with_msg('ERROR! Minimum length of packet is 25 characters.'
                      '\nPlease fix the value \'PkgSize\' and restart TFC.')




######################################################################
#                           MSG PROCESSING                           #
######################################################################

def b64e(content):
    import base64
    return base64.b64encode(content)



def crc32(content):
    import zlib
    return str(hex(zlib.crc32(content)))



def padding(string):
    length  = PkgSize - (len(string) % PkgSize)
    string += length * chr(length)

    if debugging:
        print '\nM(padding): Padded input to length of '+ str(len(string)) +' chars:\n"' + string + '"\n'

    return string



######################################################################
#                         MESSAGE TRANSMISSION                       #
######################################################################

def long_msg_preprocess(string):

    string = string.strip('\n')
    msgA   = [string[i:i + (PkgSize - 2)] for i in range(0, len(string), (PkgSize - 2) )] # Each packet is left one char shorter than padding to prevent dummy blocks.

    for i in xrange( len(msgA) ):          # Add 'a' in front of every packet.
        msgA[i] = 'a' + msgA[i]            # 'a' tells Rx.py the message should be appended to long message.

                                           # Replace 'a' with 'e' in last packet.
    msgA[-1] = 'e' + msgA[-1][1:]          # 'e' tells Rx.py the message is last one of long message, so Rx.py knows it must show the entire long message.

                                           # Replace 'a' with 'l' in first packet.
    msgA[0]  = 'l' + msgA[0][1:]           # 'l' tells Rx.py the message extends over multiple packets.

    if debugging:
        print 'M(long_msg_preprocess): Processed long message to following packets:'
        for item in msgA:
            print '"' + item + '"'

    return msgA



def long_msg_process(userInput, xmpp):

    packetList = long_msg_preprocess(userInput)

    print '\nTransferring message in ' + str(len(packetList)) + ' parts. ^C cancels'

    halt = False
    for packet in packetList:

        if halt:
            os.system('clear')
            if userInput.startswith('TFCFILE'):
                print '\nFile transmission interrupted by user.\n'
            else:
                print '\nMessage transmission interrupted by user.\n'
            return None

        try:
            keyID     = get_keyID(xmpp)

            paddedMsg = padding(packet)
            ctWithTag = encrypt(xmpp, paddedMsg)

            encoded   = b64e(ctWithTag)
            checksum  = crc32(encoded + '|' + str(keyID))

            write_keyID(xmpp, keyID + 1)
            output_message(xmpp, encoded, keyID, checksum)

            if randomSleep:
                sleepTime = random.uniform(0, maxSleepTime)
                print 'Sleeping ' + str(sleepTime) + ' seconds to obfuscate long message.'
                sleep(sleepTime)

            # Minimum sleep time ensures XMPP server is not flooded.
            sleep(lMsgSleep)

        except KeyboardInterrupt:
            halt = True



def short_msg_process(plaintext, xmpp):

    keyID     = get_keyID(xmpp)

    paddedMsg = padding('s' + plaintext) # 's' tells Rx.py the message is only one packet long.
    ctWithTag = encrypt(xmpp, paddedMsg)

    encoded  = b64e(ctWithTag)
    checksum = crc32(encoded + '|' + str(keyID))

    write_keyID(xmpp, keyID + 1)
    output_message(xmpp, encoded, keyID, checksum)



def cmd_msg_process(command):

    keyID     = get_keyID('tx.local')

    paddedCmd = padding(command)
    ctWithTag = encrypt('tx.local', paddedCmd)

    encoded   = b64e(ctWithTag)
    checksum  = crc32(encoded + '|' + str(keyID))

    write_keyID('tx.local', keyID + 1)
    output_command(encoded, keyID, checksum)



def quit_process(output = False):
    os.system('clear')
    if output:
        print '\nExiting TFC\n'
    if localTesting:
        with open('TxOutput', 'w+') as file:
            file.write('exitTFC\n')
    else:
        port.write('exitTFC\n')
    exit()



def output_command(base64msg, line, checksum):
    if localTesting:
        with open('TxOutput', 'w+') as file:
            file.write(                            '<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_command): Cmd to NH:\n<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n\n'

    else:
        port.write(                                '<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_command): Cmd to NH:\n<ctrl>'                            + base64msg + '|' + str(line) + '~' + checksum + '\n\n'



def output_message(xmpp, base64msg, line, checksum):
    if localTesting:
        with open('TxOutput', 'w+') as file:
            file.write(                            '<mesg>' + xmpp[3:] + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_message): Msg to NH:\n<mesg>' + xmpp     + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n\n'

    else:
        port.write(                                '<mesg>' + xmpp[3:] + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n')
        if debugging:
            print '\nM(output_message): Msg to NH:\n<mesg>' + xmpp     + '~' + '?TFC_' + base64msg + '|' + str(line) + '~' + checksum + '\n\n'



######################################################################
#                       COMMANDS AND FUNCTIONS                       #
######################################################################

def tab_complete(text, state):
    options = [x for x in autotabs if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None



def print_help():
    ttyW = get_terminal_width()

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
        print '/group\nList group members'                                    + le
        print '/groups\nList available groups'                                + le
        print '/group <groupname>\nSelect group'                              + le
        print '/group create <groupname> <xmpp1> <xmpp2>\nCreate new group'   + le
        print '/group add <groupname> <xmpp1> <xmpp2>\nAdd xmpp to group'     + le
        print '/group rm <groupname> <xmpp1> <xmpp2>\nRemove xmpp from group' + le
        print '/shift + PgUp/PgDn\nScroll terminal up/dn'                     + le
        print ''

    else:
        print       'List of commands:'
        print       ' /about'                                      + 16 * ' ' + 'Show information about software'
        if emergencyExit:
            print   ' /clear'                                      + 16 * ' ' + 'Clear screens'
            print   ' \'  \' (2x spacebar) '                                  + 'Emergency exit'
        else:
            print   ' /clear & \'  \''                             + 9  * ' ' + 'Clear screens'
        print       ' /file <filename>'                            + 6  * ' ' + 'Send file to recipient'
        print       ' /help'                                       + 17 * ' ' + 'Display this list of commands'
        print       ' /logging <on/off>'                           + 5  * ' ' + 'Enable/disable logging on Rx.py'
        print       ' /msg <ID/xmpp/group>'                        + 2  * ' ' + 'Change recipient'
        print       ' /names'                                      + 16 * ' ' + 'Displays available contacts'
        print       ' /paste'                                      + 16 * ' ' + 'Enable paste-mode'
        print       ' /nick <nick>'                                + 10 * ' ' + 'Change contact\'s nickname on Tx.py & Rx.py'
        print       ' /quit & /exit'                               + 9  * ' ' + 'Exits TFC'
        print       ' /group'                                      + 16 * ' ' + 'List group members'
        print       ' /groups'                                     + 15 * ' ' + 'List available groups'
        print       ' /group <groupname>'                          + 4  * ' ' + 'Select group\n'
        print       ' /group create <groupname> <xmpp1> <xmpp2>'   + 5  * ' ' + '\n Create new group called <groupname>, add list of xmpp-addresses.\n'
        print       ' /group add <groupname> <xmpp1> <xmpp2>'      + 8  * ' ' + '\n Add xmpp-addresses to group <groupname>\n'
        print       ' /group rm <groupname> <xmpp1> <xmpp2>'       + 8  * ' ' + '\n Remove xmpp-addresses from group <groupname>\n'
        print       ' shift + PgUp/PgDn'                           + 5  * ' ' + 'Scroll terminal up/down\n'



def print_list_of_contacts():
    ttyW        = get_terminal_width()
    columnList  = ['XMPP-address', 'ID', 'Nick']

    gap1        = len(max(keyFileNames, key=len)) - 2 - len(columnList[0])
    header      = columnList[0] + gap1 * ' ' + columnList[1] + '  ' + columnList[2]

    print header + '\n' + ttyW * '-'

    for xmpp in keyFileNames:
        ID   = keyFileNames.index(xmpp)
        nick = get_nick(xmpp[:-2])
        xmpp = xmpp[3:][:-2]
        if nick != 'tx.local':
            gap2 = int(header.index(columnList[1][0])) - len(xmpp)
            gap3 = int(header.index(columnList[2][0])) - len(xmpp) - gap2 - len(str(ID))
            print xmpp + gap2 * ' ' + str(ID) + gap3 * ' ' + nick
        idSelDist = int(header.index(columnList[1][0]))

    return idSelDist



def select_contact(idSelDist='', contactNo='', menu=True):

    contactSelected = False
    while not contactSelected:
        try:
            # If no parameter about contact selection is passed to function, ask for input
            if contactNo == '':
                selection = (raw_input('\nSelect contact:' + (idSelDist - len('Select contact:') ) * ' ') )

                intSelection = int(selection)
            else:
                intSelection = int(contactNo)


        # Error handling if selection was not a number.
        except ValueError:
            if menu:
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                raise ValueError, 'Invalid number'


        # Clean exit.
        except KeyboardInterrupt:
            exit_with_msg('Exiting TFC.', False)


        # Check that integer is within allowed bounds.
        if (intSelection < 0) or (intSelection > get_contact_quantity()):
            if menu:
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                raise ValueError, 'Invalid number'


        # Check that selction number was valid.
        try:
            keyFile = keyFileNames[intSelection]
        except IndexError:
            if menu:
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                print '\nError: Invalid contact selection\n'

        xmpp = keyFile[:-2]
        nick = get_nick(xmpp)


        # Check that user has not selected local contact.
        if xmpp == 'tx.local':
            if menu:
                contactNo = ''
                os.system('clear')
                print 'TFC ' + version + ' || Tx.py' + '\n\nError: Invalid contact selection \'' + selection + '\'\n'
                print_list_of_contacts()
                continue
            else:
                raise ValueError, 'Invalid number'

        contactSelected = True

    return xmpp, nick



def exit_with_msg(message, error=True):
    os.system('clear')
    if error:
        print '\n' + message + ' Exiting.\n'
    else:
        print '\n' + message + '\n'
    exit()



######################################################################
#                          GROUP MANAGEMENT                          #
######################################################################

def group_create(groupName, newMembers = []):

    if os.path.isfile('g.' + groupName + '.tfc'):
        if not (raw_input('Group \'' + groupName + '\' already exists. Type YES to overwrite: ') == 'YES'):
            return False

    with open('g.' + groupName + '.tfc', 'w+') as file:
        if newMembers:
            for user in newMembers:
                file.write(user + '\n')
            sort_group(groupName)
        else:
            pass

    return True



def group_add_member(groupName, addList):
    try:
        gFile    = []
        existing = []
        added    = []
        unknown  = []

        with open('g.' + groupName + '.tfc', 'a+') as file:
            groupFile = file.readlines()

            for contact in groupFile:
                gFile.append(contact.strip('\n'))

            for member in addList:
                member   = member.strip('\n').strip(' ')
                memberKf = 'tx.' + member + '.e'

                if member in gFile:
                    existing.append(member)

                else:
                    if memberKf in keyFileNames:
                        file.write(member + '\n')
                        added.append(member)

                    else:
                        unknown.append(member)

            os.system('clear')

            if added:
                print 'Members added to group \'' + groupName + '\':'
                for member in added:
                    print '   ' + member
                print '\n'

                sort_group(groupName)

            if unknown:
                print 'Unknown contacts not added to group \'' + groupName + '\':'
                for member in unknown:
                    print '   ' + member
                print '\n'

            if existing:
                print 'Already existing users in group \'' + groupName + '\':'
                for member in existing:
                    print '   ' + member
                print '\n'

    except IOError:
        exit_with_msg('ERROR! Group file g.' + groupName + '.tfc could not be loaded.')



def group_rm_member(groupName, rmList):
    try:
        memberList = []
        removed    = []
        unknown    = []

        with open('g.' + groupName + '.tfc', 'r') as file:
            groupFile = file.readlines()

        for member in groupFile:
            member = member.strip('\n')
            memberList.append(member)

        with open('g.' + groupName + '.tfc', 'w') as file:
            for member in memberList:
                if member in rmList:
                    removed.append(member)
                else:
                    file.write(member + '\n')

        for member in rmList:
            if member not in memberList:
                unknown.append(member)

        os.system('clear')

        if removed:
            print 'Members removed from group \'' + groupName + '\':'
            for member in removed:
                print '   ' + member
        else:
            print 'Nothing removed from group \'' + groupName + '\':'

        if unknown:
            print '\n\nUnknown contacts:'
            for member in unknown:
                print '   ' + member

    except IOError:
        exit_with_msg('ERROR! Group file g.' + groupName + '.tfc could not be loaded.')



def sort_group(groupName):
    try:
        with open('g.' + groupName + '.tfc', 'r') as file:
            members = file.readlines()
            members.sort()

        with open('g.' + groupName + '.tfc', 'w') as file:
            for member in members:
                file.write(member)

    except IOError:
        exit_with_msg('ERROR! Group file g.' + selectedGroup + '.tfc could not be loaded.')



def get_group_list(output):
    gFileNames = []
    for file in os.listdir('.'):
        if file.startswith('g.') and file.endswith('.tfc'):
            gFileNames.append(file[2:][:-4])

    if not gFileNames and output:
        print '\nThere are currently no groups.\n'

    return gFileNames



def get_group_members(groupName, output=True):
    try:
        groupList = []

        with open('g.' + groupName + '.tfc', 'r') as file:
            members = file.readlines()

        for member in members:
            groupList.append(member.strip('\n'))

        if not groupList and output:
            print '\nGroup is empty. Add contacts to group with command\n   /group add <group name> <xmpp>\n'

        return groupList

    except IOError:
        exit_with_msg('ERROR! Group file g.' + selectedGroup + '.tfc could not be loaded.')



######################################################################
#                              PRE LOOP                              #
######################################################################

# Set initial values.
os.chdir(sys.path[0])
pastemode     = False
selectedGroup = ''

# Run initial checks.
chk_pkgSize()
search_keyfiles()

# Load initial data.
keyFileNames, contacts = get_keyfile_list()
add_keyfiles(keyFileNames)

# Initialize autotabbing.
readline.set_completer(tab_complete)
readline.parse_and_bind('tab: complete')

os.system('clear')
print 'TFC ' + version + ' || Tx.py ' + 3 * '\n'

# Contact selection.
idSelDist  = print_list_of_contacts()
xmpp, nick = select_contact(idSelDist)



######################################################################
#                                LOOP                                #
######################################################################

os.system('clear')

while True:

    # Refresh lists.
    autotabs      = get_autotabs(contacts)
    groupFileList = get_group_list(False)

    if pastemode:
        try:
            os.system('clear')
            print 'You\'re now in paste mode:\n'\
                  '2x ^D sends message.\n'      \
                  '   ^C exits paste mode.\n'   \
                  'Paste content to ' + nick + ':\n'

            lines     = sys.stdin.readlines()
            userInput = '\n' + ''.join(lines)
            print '\nSending...'
            sleep(0.1)

        except KeyboardInterrupt:
            pastemode = False
            userInput = ''
            print '\nClosing paste mode...'
            sleep(0.4)
            os.system('clear')
            continue

    if not pastemode:
        try:
            userInput = raw_input('Msg to ' + nick + ': ')

        except KeyboardInterrupt:
            exit_with_msg('Exiting TFC.', False)



    ##################################################################
    #                    GROUP MANAGEMENT COMMANDS                   #
    ##################################################################

    # List group members.
    if userInput in ['/group', '/group ']:

        if selectedGroup == '':
            print '\nNo group selected\n'
            continue

        else:
            membersOfGroup = get_group_members(selectedGroup)

        if membersOfGroup:
            os.system('clear')
            print '\nMembers of selected group \'' + selectedGroup + '\':'
            for member in membersOfGroup:
                print '   ' + member
            print ''
        continue


    # List available groups.
    if userInput == '/groups':
        groupFileList = get_group_list(True)
        if groupFileList:
            os.system('clear')
            print 'Available groups are: '
            for group in groupFileList:
                print '   ' + group
        print ''
        continue


    # Create new group.
    if userInput.startswith('/group create '):
        userInput = ' '.join(userInput.split())


        # Create list of names group can not have.
        reservedNames = ['create', 'add', 'rm']
        for fileName in keyFileNames:
            reservedNames.append(get_nick(fileName[:-2])) # Append nicknames.
            reservedNames.append(fileName[:-2])           # Append XMPP-file.
            reservedNames.append(fileName[3:][:-2])       # Append XMPP-addr.


        # Check that group name is not reserved.
        newGroupName = userInput.split(' ')[2]
        if newGroupName == '':
            print '\nError: Group name can\'t be empty.\n'
            continue
        if newGroupName in reservedNames:
            print '\nError: Group name can\'t be command, nick or XMPP-address.\n'
            continue


        os.system('clear')
        memberList = userInput.split(' ')
        members    = []
        notAdded   = []
        i          = 3

        while i < len(memberList):
            newMember = str(memberList[i])
            mbrFile   = 'tx.' + newMember + '.e'
            i += 1

            if (mbrFile in keyFileNames) and (mbrFile not in ['tx.local.e', 'rx.local.e']):
                members.append(newMember)
            else:
                notAdded.append(newMember)


        if group_create(newGroupName, members):

            if members:
                print '\nCreated group \'' + newGroupName + '\' with following members:'
                for member in members:
                    print '   ' + member
                print ''

            else:
                print '\nCreated empty group \'' + newGroupName + '\'\n'

            if notAdded:
                print '\nUnknown contacts not added to group \'' + newGroupName + '\':'
                for member in notAdded:
                    print '   ' + member
                print ''
            continue

        else:
            print '\nGroup generation cancelled.\n'
            continue


    # Add member to group.
    if userInput.startswith('/group add '):

        userInput = ' '.join(userInput.split())
        groupName = userInput.split(' ')[2]

        xmppList  = []
        i         = 3

        while i < len(userInput.split(' ')):
            member  = userInput.split(' ')[i]
            mbrFile = 'tx.' + member + '.e'
            i      += 1

            if mbrFile not in ['tx.local', 'rx.local']:
                xmppList.append(member)

        group_add_member(groupName, xmppList)
        continue


    # Remove member from group.
    if userInput.startswith('/group rm '):

        userInput     = ' '.join(userInput.split())
        selectedGroup = userInput.split(' ')[2]

        if not selectedGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue

        rmList = []
        i      = 3
        while i < len(userInput.split(' ')):
            member = userInput.split(' ')[i]
            i += 1
            rmList.append(member)

        group_rm_member(selectedGroup, rmList)
        print ''
        continue


    # Select group.
    if userInput.startswith('/group '):

        userInput = ' '.join(userInput.split())
        newGroup  = userInput.split(' ')[1]

        if newGroup == '':
            print '\nError: Invalid group\n'
            continue

        if not newGroup in groupFileList:
            print '\nError: Invalid group\n'
            continue

        else:
            selectedGroup = nick = newGroup
            os.system('clear')
            print 'Now sending messages to group \'' + nick + '\'\n'
            continue



    ##################################################################
    #                      OTHER LOCAL COMMANDS                      #
    ##################################################################

    if emergencyExit:
        if userInput == '  ':
            quit_process(False)


    if userInput == '  ' or userInput == '/clear':
        if localTesting:
            with open('TxOutput', 'w+') as file:
                file.write('clearScreen ' + xmpp + '\n')
        else:
            port.write('clearScreen ' + xmpp + '\n')

        os.system('clear')
        continue

    if userInput == '/quit' or userInput == '/exit':
        quit_process(True)


    if userInput == '':
        continue


    if userInput == '/debugging on':
        debugging = True
        os.system('clear')
        print '\nDebugging enabled\n'
        continue


    if userInput == '/debugging off':
        debugging = False
        os.system('clear')
        print '\nDebugging disabled\n'
        continue


    if userInput == '/help':
        os.system('clear')
        print_help()
        continue


    if userInput == '/paste':
        pastemode = True
        continue


    if userInput == '/about':
        os.system('clear')
        print ' Tinfoil Chat ' + version + '\n'
        print ' https://github.com/maqp/tfc-cev/\n'
        print ' cs.helsinki.fi/u/oottela/tfc.pdf'
        print '                         /tfc-manual.pdf\n\n'
        continue


    if userInput == '/names':
        os.system('clear')
        print ''
        print_list_of_contacts()
        print ''
        continue


    if userInput.startswith('/msg '):
        try:
            selection = str(userInput.split(' ')[1])

            if selection in groupFileList:
                nick = selectedGroup = selection
                os.system('clear')
                print 'Now sending messages to group \'' + selectedGroup + '\'\n'
                continue


            if selection in contacts:
                    if selection != 'tx.local':
                        xmpp = 'tx.' + selection
                        nick = get_nick(xmpp)
                        selectedGroup = ''
                        os.system('clear')
                        print 'Now sending messages to ' + nick + ' (' + xmpp[3:] + ')\n'
                        continue

            else:
                try:
                    xmpp, nick = select_contact('', selection, False)

                except ValueError:
                    print '\nError: Invalid contact selection.\n'
                    continue

                except IndexError:
                    print '\nError: Invalid contact selection.\n'
                    continue

                selectedGroup = ''
                os.system('clear')
                print 'Now sending messages to ' + nick + ' (' + xmpp + ')\n'
                continue

        except ValueError:
            continue
        except AttributeError:
            pass
        except UnboundLocalError:
            continue



    ##################################################################
    ##                      COMMANDS TO RX.py                       ##
    ##################################################################

    if userInput.startswith('/nick ') or userInput.startswith('/logging '):
        command    = ''

        # Check that local keyfile exists.
        if not os.path.isfile('tx.local.e'):
            print '\nError: Keyfile \'tx.local.e\' was not found. Command was not sent.\n'
            continue


        ################
        #     NICK     #
        ################
        if userInput.startswith('/nick '):
            if nick in groupFileList:
                print '\nGroup is selected, no nick was changed.\n'
                continue

            if len(userInput) < 7:
                print 'Error: Can\'t give empty nick.'
                continue

            newNick = userInput.split(' ')[1]

            # Check that specified nick is acceptable.
            if '=' in newNick or '/' in newNick:
                print '\nError: Nick can not contain reserved characters / or =\n'
                continue
            if (newNick == 'tx.local') or (newNick == 'rx.local'):
                print '\nError: Can\'t give reserved nick of local.e to contact.\n'
                continue
            if newNick in groupFileList:
                print '\nError: Nick is in use for group.\n'
                continue

            write_nick(xmpp, newNick)
            nick = get_nick(xmpp)

            os.system('clear')
            print '\nChanged ' + xmpp[3:] + ' nick to ' + nick + '\n'
            command = 'rx.' + xmpp[3:] + '/nick=' + nick


        ###################
        #     LOGGING     #
        ###################
        if userInput.startswith('/logging '):

            value = str(userInput.split(' ')[1])

            if value   == 'on':
                command = 'logson'

            elif value == 'off':
                command = 'logsoff'

            else:
                print '\nError: Invalid command\n'
                continue


        ########################
        #    COMMAND PACKET    #
        ########################

        cmd_msg_process(command)

        continue

    #############################
    #     FILE TRANSMISSION     #
    #############################

    if userInput.startswith('/file '):

        fileName = userInput.split(' ')[1]

        if nick in groupFileList:
            sendTarget = 'all members of group \'' + nick + '\''
        else:
            sendTarget = xmpp[3:]


        if raw_input('\nThis will send file \'' + fileName + '\' to ' + sendTarget + '.\nAre you sure? Type upper case YES to continue: ') == 'YES':
            subprocess.Popen('base64 ' + fileName + ' > TFCtmpFile', shell=True).wait()

            with open('TFCtmpFile', 'r') as file:
                b64File     = file.readlines()
                fileMessage = ''
                for line in b64File:
                    fileMessage += line


            if fileMessage == '':
                os.system('clear')
                print 'Error: No file \'' + fileName + '\' found. Transmission aborted.\n'


            userInput = 'TFCFILE' + fileMessage
            subprocess.Popen('shred -n ' + str(shredIterations) + ' -z -u TFCtmpFile', shell=True).wait()

            os.system('clear')
            print '\nSending file ' + fileName + '\n'

        else:
            print '\nFile sending aborted\n'
            time.sleep(0.4)
            continue

    if userInput.startswith('/') and not userInput.startswith('/file '):
        os.system('clear')
        print '\nError: Unknown command \'' + userInput + '\'\n'
        continue



    ##################################################################
    #                      MULTICASTED MESSAGES                      #
    ##################################################################

    if nick in groupFileList:

        groupMemberList = get_group_members(selectedGroup, False)

        if not groupMemberList:
            os.system('clear')
            print 'Current group is empty. No message was sent.\n'
            continue

        for member in groupMemberList:
            print '           > ' + member
            xmpp = 'tx.' + member

            if len(userInput) > PkgSize:
                long_msg_process(userInput, xmpp)

            else:
                short_msg_process(userInput, xmpp)

        sleep(0.1)

        print ''



    ##################################################################
    #                        STANDARD MESSAGES                       #
    ##################################################################

    else:
        if len(userInput) > PkgSize:
            long_msg_process(userInput, xmpp)

        else:
            short_msg_process(userInput, xmpp)



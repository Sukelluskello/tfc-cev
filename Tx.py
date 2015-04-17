#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-CEV (Cascading Encryption Version) || Tx.py
version = '0.5.4 beta'

"""
GPL Licence

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

# UI Settings
clear_input_screen = False           # When enabled, clears input screen after msg/cmd.
print_g_contacts   = True            # When printing groups, also print group members.


# Security settings
emergency_exit     = False           # Enable emergency exit with double space as message.
shred_iterations   = 3               # The number of iterations deleted files are
                                     # overwritten with secure delete / shred.

# Packet settings
pkg_size           = 140             # Default length of payload.

l_msg_sleep        = 0.5             # Minimum sleep time between consecutive packets
                                     # ensures XMPP server is not flooded.

# Metadata hiding features
random_sleep       = False           # Random sleep between long msg / file transmission.
                                     # Also works between constant transmission packets.

max_sleep_time     = 13.0            # Maximum random_sleep time.

c_transmission     = False           # Constant transmission of messages and commands.
ct_static_sleep    = 4.0             # Sleep time between coin tosses.

jitter_max         = 0.3             # Jitter between sent messages and commands makes it
jitter_min         = 0.0             # harder to detect when communication is taking place.


# Developer tools
debugging          = False           # Set true to enable verbose messaging
                                     # about inner operations in Rx.py.

# Local testing mode: enabled when testing TFC on single computer.
local_testing = False


# Serial port settings
serial_baudrate    = 9600            # Serial device speed.
serial_device      = '/dev/ttyAMA0'  # The serial device Rx.py reads data from.


######################################################################
#                                 IMPORTS                            #
######################################################################

import base64
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
import zlib

from multiprocessing import (Process, Queue)

# Import crypto libraries.
from Crypto.Cipher import AES

try:
    from salsa20 import XSalsa20_xor
except AssertionError:
    os.system('clear')
    print '\nCRITICAL ERROR! Salsa20 library is corrupted.\nExiting Tx.py\n'
    exit()

try:
    from twofish import Twofish
except ImportError:
    os.system('clear')
    print '\nCRITICAL ERROR! Twofish library is corrupted.\nExiting Tx.py\n'
    exit()


######################################################################
#                              CRYPTOGRAPHY                          #
######################################################################

# Keccak CTR
class KeccakError(Exception):
    """
    Class of error used in the Keccak implementation.

    Use: raise KeccakError.KeccakError("Text to be displayed")
    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Keccak:
    """
    Class implementing the Keccak sponge function.

    Licence is listed in file LISENCE.md
    """

    def __init__(self, b=1600):
        """
        Constructor:

        b: parameter b, must be 25, 50, 100, 200, 400, 800 or 1600 (default value).
        """

        self.setB(b)

    def setB(self, b):
        """
        Set the value of the parameter b (and thus w,l and nr).

        :param b: parameter b, must be choosen among [25, 50, 100, 200, 400, 800, 1600].
        """

        if b not in [25, 50, 100, 200, 400, 800, 1600]:
            raise KeccakError.KeccakError('b value not supported - use 25, 50, 100, 200, 400, 800 or 1600')

        # Update all the parameters based on the used value of b.
        self.b  = b
        self.w  = b // 25
        self.l  = int(math.log(self.w, 2))
        self.nr = 12 + 2 * self.l

    # Constants

    # Round constants
    RC = [0x0000000000000001,
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

    # Rotation offsets
    r = [[ 0, 36,  3, 41, 18],
         [ 1, 44, 10, 45,  2],
         [62,  6, 43, 15, 61],
         [28, 55, 25, 21, 56],
         [27, 20, 39,  8, 14]]

    # Generic utility functions.
    def rot(self, x, n):
        """
        Bitwise rotation (to the left) of n bits
        considering the string of bits is w bits long.

        :param x: [not defined]
        :param n: [not defined]
        """

        n = n % self.w
        return ((x >> (self.w - n)) + (x << n)) % (1 << self.w)

    def fromHexStringToLane(self, string):
        """
        Convert a string of bytes written in hexadecimal to a lane value.

        :param string: [not defined]
        """

        # Check that the string has an even number of characters i.e. whole number of bytes.
        if len(string) % 2 != 0:
            raise KeccakError.KeccakError("The provided string does not end with a full byte")

        # Perform the modification.
        temp = ''
        nrBytes = len(string) // 2
        for i in range(nrBytes):
            offset = (nrBytes - i - 1) * 2
            temp += string[offset:offset + 2]
        return int(temp, 16)

    def fromLaneToHexString(self, lane):
        """
        Convert a lane value to a string of bytes written in hexadecimal.

        :param lane: [not defined]
        """

        laneHexBE = (("%%0%dX" % (self.w // 4)) % lane)

        # Perform the modification.
        temp = ''
        nrBytes = len(laneHexBE) // 2
        for i in range(nrBytes):
            offset = (nrBytes - i - 1) * 2
            temp += laneHexBE[offset:offset + 2]
        return temp.upper()

    def printState(self, state, info):
        """
        Print on screen the state of the sponge function preceded by string info.

        :param state: State of the sponge function.
        :param info:  A string of characters used as identifier.
        """

        print("Current value of state: %s" % info)
        for y in range(5):
            line = []
            for x in range(5):
                line.append(hex(state[x][y]))
            print('\t%s' % line)

    # Conversion functions String <-> Table (and vice-versa).

    def convertStrToTable(self, string):
        """
        Convert a string of bytes to its 5x5 matrix representation.

        :param string: string of bytes of hex-coded bytes (e.g. '9A2C...').
        """

        # Check input paramaters.
        if self.w % 8 != 0:
            raise KeccakError("w is not a multiple of 8")
        if len(string) != 2 * self.b // 8:
            raise KeccakError.KeccakError("String can't be divided in 25 blocks of w \
                                           bits i.e. string must have exactly b bits")

        # Convert
        output = [[0, 0, 0, 0, 0],
                  [0, 0, 0, 0, 0],
                  [0, 0, 0, 0, 0],
                  [0, 0, 0, 0, 0],
                  [0, 0, 0, 0, 0]]

        for x in range(5):
            for y in range(5):
                offset = 2 * ((5 * y + x) * self.w) // 8
                output[x][y] = self.fromHexStringToLane(string[offset:offset + (2 * self.w // 8)])
        return output

    def convertTableToStr(self, table):
        """
        Convert a 5x5 matrix representation to its string representation.

        :param table: [not defined]
        """

        # Check input format.
        if self.w % 8 != 0:
            raise KeccakError.KeccakError("w is not a multiple of 8")
        if (len(table) != 5) or (False in [len(row) == 5 for row in table]):
            raise KeccakError.KeccakError("table must be 5x5")

        # Convert
        output = [''] * 25
        for x in range(5):
            for y in range(5):
                output[5 * y + x] = self.fromLaneToHexString(table[x][y])
        output = ''.join(output).upper()
        return output

    def Round(self, A, RCfixed):
        """
        Perform one round of computation as defined in the Keccak-f permutation.

        :param A:       Current state (5x5 matrix).
        :param RCfixed: Value of round constant to use (integer).
        """

        # Initialisation of temporary variables.
        B = [[0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0]]
        C =  [0, 0, 0, 0, 0]
        D =  [0, 0, 0, 0, 0]

        # Theta step
        for x in range(5):
            C[x] = A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4]

        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ self.rot(C[(x + 1) % 5], 1)

        for x in range(5):
            for y in range(5):
                A[x][y] = A[x][y] ^ D[x]

        # Rho and Pi steps
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = self.rot(A[x][y], self.r[x][y])

        # Chi step
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])

        # Iota step
        A[0][0] = A[0][0] ^ RCfixed

        return A

    def KeccakF(self, A, verbose=False):
        """
        Perform Keccak-f function on the state A.

        :param A:       5x5 matrix containing the state.
        :param verbose: A boolean flag activating the printing of intermediate computations.
        """

        if verbose:
            self.printState(A, "Before first round")

        for i in range(self.nr):
            # NB: result is truncated to lane size
            A = self.Round(A, self.RC[i] % (1 << self.w))

            if verbose:
                  self.printState(A, "Status end of round #%d/%d" % (i + 1, self.nr))

        return A

    # Padding rule

    def pad10star1(self, M, n):
        """
        Pad M with the pad10*1 padding rule to reach a length multiple of r bits.

        :param n: Length in bits (must be a multiple of 8).
        :param M: Message pair (length in bits, string of hex characters ('9AFC...').

        Example:  pad10star1([60, 'BA594E0FB9EBBD30'],8) returns 'BA594E0FB9EBBD93'.
        """

        [my_string_length, my_string] = M

        # Check the parameter n.
        if n % 8 != 0:
            raise KeccakError.KeccakError("n must be a multiple of 8")

        # Check the length of the provided string.
        if len(my_string) % 2 != 0:

            # Pad with one '0' to reach correct length (don't know test vectors coding).
            my_string = my_string + '0'

        if my_string_length > (len(my_string) // 2 * 8):
            raise KeccakError.KeccakError("The string is too short to contain the number of bits announced")

        nr_bytes_filled = my_string_length // 8
        nbr_bits_filled = my_string_length % 8
        l = my_string_length % n
        if (n - 8) <= l <= (n - 2):
            if nbr_bits_filled == 0:
                my_byte = 0
            else:
                my_byte = int(my_string[nr_bytes_filled * 2:nr_bytes_filled * 2 + 2], 16)
            my_byte   = (my_byte >> (8 - nbr_bits_filled))
            my_byte   = my_byte + 2 ** nbr_bits_filled + 2 ** 7
            my_byte   = "%02X" % my_byte
            my_string = my_string[0:nr_bytes_filled * 2] + my_byte
        else:
            if nbr_bits_filled == 0:
                my_byte = 0
            else:
                my_byte = int(my_string[nr_bytes_filled * 2:nr_bytes_filled * 2 + 2], 16)
            my_byte   = (my_byte >> (8 - nbr_bits_filled))
            my_byte   = my_byte + 2 ** nbr_bits_filled
            my_byte   = "%02X" % my_byte
            my_string = my_string[0:nr_bytes_filled * 2] + my_byte
            while(8 * len(my_string) // 2) % n < (n - 8):
                my_string = my_string + '00'
            my_string = my_string + '80'

        return my_string

    def Keccak(self, M, r=1024, c=576, n=1024, verbose=False):
        """
        Compute the Keccak[r,c,d] sponge function on message M.

        :param verbose: Print the details of computations (default: False).
        :param n:       Length of output in bits          (default: 1024).
        :param c:       Capacity in bits                  (default: 576).
        :param r:       Bitrate in bits                   (default: 1024).
        :param M:       Message pair (length in bits, string of hex characters ('9AFC...').
        """

        # Check the inputs
        if (r < 0) or (r % 8 != 0):
            raise KeccakError.KeccakError('r must be a multiple of 8 in this implementation')
        if n % 8 != 0:
            raise KeccakError.KeccakError('OutputLength must be a multiple of 8')
        self.setB(r + c)

        if verbose:
            print("Create a Keccak function with (r=%d, c=%d (i.e. w=%d))" % (r, c, (r + c) // 25))

        # Compute lane length (in bits).
        w = (r + c) // 25

        # Initialisation of state
        S = [[0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0],
             [0, 0, 0, 0, 0]]

        # Padding of messages
        P = self.pad10star1(M, r)

        if verbose:
            print("String ready to be absorbed: %s (will be completed by %d x '00')" % (P, c // 8))

        # Absorbing phase
        for i in range((len(P) * 8 // 2) // r):
            Pi = self.convertStrToTable(P[i * (2 * r // 8):(i + 1) * (2 * r // 8)] + '00' * (c // 8))

            for y in range(5):
                for x in range(5):
                    S[x][y] = S[x][y] ^ Pi[x][y]
            S = self.KeccakF(S, verbose)

        if verbose:
            print("Value after absorption : %s" % (self.convertTableToStr(S)))

        # Squeezing phase
        Z = ''
        outputLength = n
        while outputLength > 0:
            string = self.convertTableToStr(S)
            Z      = Z + string[:r * 2 // 8]
            outputLength -= r
            if outputLength > 0:
                S = self.KeccakF(S, verbose)

            # NB: done by block of length r, could have to
            # be cut if outputLength is not a multiple of r.

        if verbose:
            print("Value after squeezing : %s" % (self.convertTableToStr(S)))

        return Z[:2 * n // 8]


def keccak256(hash_input):
    """
    Calculate 256 bit Keccak (SHA3) checksum from input.

    :param hash_input: The value to be digested.
    :return:           256-bit Keccak-digest in hex format.

    Keccak is a hash function that uses a sponge construction; It is the SHA3
    standard set by NIST in 2012. This configuration runs Keccak with rate of
    1088 and capacity of 512 to provide 256-bit collision resistance and
    256-bit (second) preimage resistance.

    The rate and capacity are set according to the reccomendatios of Keccak
    developer team: http://keccak.noekeon.org/Keccak-submission-3.pdf // page 2

    The length of digest is 256 bits and it is output in 64 hex numbers.
    """

    # Verify input parameter type.
    if not isinstance(hash_input, str):
        exit_with_msg('CRITICAL ERROR! M(keccak256): Wrong input type.')

    # Convert input to hexadecimal format.
    hexmsg = binascii.hexlify(hash_input)

    # Return the 256-bit digest.
    return Keccak().Keccak(((8 * len(hash_input)), hexmsg), 1088, 512, 256)


def keccak_encrypt(plaintext, hex_key):
    """
    Encrypt plaintext with Keccak as PRF (CTR mode).

    :param plaintext: Input to be encrypted.
    :param hex_key:   Independent 256-bit encryption key.
    :return:          Keccak ciphertext.

    The used Keccak-library is the official version written by Renaud Bauvin.
    The PRF is used in CTR mode: The implementation padds the plaintext to
    256 bit blocks, concatenates the 256-bit symmetric key with 256-bit nonce
    loaded from /dev/urandom to produce a 512-bit IV. For each block of
    plaintext, a matching length digest is appended to key stream. The next
    digest is generated by hashing the most recent digest together with key.
    Once the keystream is as long as the plaintext, the two are XORred together
    to produce the ciphertext. In last step, the nonce is appended to the
    ciphertext.
    """

    # Verify input parameter types.
    if not (isinstance(plaintext, str) and isinstance(hex_key, str)):
        exit_with_msg('CRITICAL ERROR! M(keccak_encrypt): Wrong input type.')

    # Add padding to plaintext (256-bit block-size).
    length     = 32 - (len(plaintext) % 32)
    plaintext += length * chr(length)

    # Convert hexadecimal key to binary data.
    key        = binascii.unhexlify(hex_key)

    # Generate 256-bit nonce.
    nonce      = os.urandom(32)

    # Generate 512-bit IV.
    iv         = (key + nonce)

    # Keccak takes the IV and outputs a 256 bit keystream block #1.
    step       = keccak256(iv)

    i          = 0
    keystream  = ''
    step_list  = []

    # For n-byte plaintext, n/32 additional rounds are
    # needed to generate the proper length keystream.
    while i < (len(plaintext) / 32):
        keystream += step
        step       = keccak256(key + step)
        i         += 1

        # Check similar key stream block hasn't been generated earlier.
        if step in step_list:
            exit_with_msg('CRITICAL ERROR! M(keccak_encrypt): Keccak keystream block was used twice.')
        else:
            step_list.append(step)

    # Double-check key stream block is not used twice.
    try:
        seen = set()
        assert not any(i in seen or seen.add(i) for i in step_list)

    except AssertionError:
        exit_with_msg('CRITICAL ERROR! M(keccak_encrypt): Keccak keystream block was used twice.')

    # Convert key from hex format to binary.
    keystream_bin = binascii.unhexlify(keystream)

    ciphertext    = ''

    # XOR keystream with plaintext to generate ciphertext.
    if len(plaintext) == len(keystream_bin):
        ciphertext = ''.join(chr(ord(p) ^ ord(k)) for p, k in zip(plaintext, keystream_bin))

    else:
        exit_with_msg('CRITICAL ERROR! M(keccak_encrypt): Keccak plaintext - keystream length mismatch.')

    return nonce + ciphertext


def keccak_decrypt(ctext, hex_key):
    """
    Decrypt ciphertext with Keccak in CTR mode. (Used in Tx.py for self testing.)

    :param ctext:   Ciphertext, encrypted test string.
    :param hex_key: 256-bit self-test encryption key.
    :return:        Plaintext to be compared.

    The used Keccak-library is the official version written by Renaud Bauvin.
    The PRF is used in CTR mode: The implementation separates the nonce from
    the ciphertext and appends it to the 256-bit symmetric key to produce the
    512-bit IV that is then hashed to produce the first keystream block. For
    each consecutive block of ciphertext a block of key stream is generated
    by hashing the key appended with the most recent digest. Once the
    keystream is as long as the ciphertext, the two are XORred together to
    produce the plaintext. In last step, the padding is removed from plaintext.
    """

    # Verify input parameter types.
    if not (isinstance(ctext, str) and isinstance(hex_key, str)):
        exit_with_msg('CRITICAL ERROR! M(keccak_decrypt): Wrong input type.')

    # Convert hexadecimal key to binary data.
    key       = binascii.unhexlify(hex_key)

    # Separate 256-bit nonce from ciphertext.
    nonce     = ctext[:32]
    ctext     = ctext[32:]

    # Generate 512-bit IV.
    iv        = (key + nonce)

    # Keccak takes the IV and outputs a 256 bit keystream block #1.
    step      = keccak256(iv)

    i         = 0
    keystream = ''
    step_list = []

    # For n-byte ciphertext, n/32 additional rounds is
    # needed to generate proper length keystream.
    while i < (len(ctext) / 32):
        keystream += step
        step       = keccak256(key + step)

        # Check similar key stream block hasn't been generated earlier.
        if step in step_list:
            exit_with_msg('CRITICAL ERROR! M(keccak_decrypt): Keccak keystream block was used twice.')
        else:
            step_list.append(step)

        i += 1

    # Double check key stream block is not used twice.
    try:
        seen = set()
        assert not any(i in seen or seen.add(i) for i in step_list)

    except AssertionError:
        exit_with_msg('CRITICAL ERROR! M(keccak_decrypt): Keccak keystream block was used twice.')

    # Convert key from hex format to binary.
    keystream_bin = binascii.unhexlify(keystream)

    plaintext     = ''

    # XOR keystream with ciphertext to obtain plaintext.
    if len(ctext) == len(keystream_bin):
        plaintext = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(ctext, keystream_bin))

    else:
        exit_with_msg('CRITICAL ERROR! M(keccak_decrypt): Keccak ciphertext - keystream length mismatch.')

    # Remove padding.
    plaintext = plaintext[:-ord(plaintext[-1:])]

    return plaintext


def self_test_keccak_ctr():
    """
    Run Keccak CTR mode self test.

    :return: None.
    """

    # Test the Keccak hash algorithm.
    print 'Keccak-F    self test initialized'

    test_input  = 'Keccak initialization test'
    test_vector = '118A7B87E6CB739423374CD3498E2501FD12E3B02B96278820B19677AAE68809'

    if keccak256(test_input) != test_vector:
        exit_with_msg('CRITICAL ERROR! Keccak class is corrupted.')
    else:
        print 'Keccak-F    self test successful'

    # Test the Keccak CTR implementation.
    print 'Keccak-CTR  self test initializated'
    test_pt  = 'Keccak-CTR initialization test'
    test_key = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    test_ct  = keccak_encrypt(test_pt, test_key)
    dec_pt   = keccak_decrypt(test_ct, test_key)

    if test_pt != dec_pt:
        exit_with_msg('CRITICAL ERROR! Keccak CTR self test failed.')
    else:
        print 'Keccak-CTR  self test successful'
        return None


# XSalsa20
def salsa20_encrypt(plaintext, hex_key):
    """
    Encrypt plaintext with XSalsa20.

    :param plaintext: Input to be encrypted.
    :param hex_key:   Independent 256-bit encryption key.
    :return:          XSalsa20 ciphertext.

    The XSalsa20 is a stream cipher based on add-rotate-XOR (ARX).
    It is used with a /dev/urandom spawned, 192-bit nonce
    (length specified in libsodium). The independent, symmetric,
    256-bit key is used together with nonce to produce a key stream,
    which is then XORred with the plaintext to produce ciphertext.
    In last step the nonce is appended to the ciphertext.
    """

    # Verify input parameter types.
    if not isinstance(plaintext, str) or not isinstance(hex_key, str):
        exit_with_msg('CRITICAL ERROR! M(salsa20_encrypt): Wrong input type.')

    # Convert hexadecimal key to bitstring.
    key = binascii.unhexlify(hex_key)

    # Generate unique nonce.
    iv  = os.urandom(24)

    # XOR plaintext with keystream to acquire ciphertext.
    ciphertext = XSalsa20_xor(plaintext, iv, key)

    return iv + ciphertext


def salsa20_decrypt(ctext, hex_key):
    """
    Decrypt ciphertext with Salsa20. (Used in Tx.py for self testing.)

    :param ctext:   Encrypted test string.
    :param hex_key: 256-bit self-test encryption key.
    :return:        Plaintext to be compared.

    The XSalsa20 is a stream cipher based on add-rotate-XOR (ARX).
    In decryption process, the 192-bit nonce is separated from
    siphertext. The independent, symmetric, 256-bit key is used
    together with nonce to produce a key stream, which is then
    XORred with the ciphertext to produce the plaintext.
    """

    # Verify input parameter types.
    if not isinstance(ctext, str) or not isinstance(hex_key, str):
        exit_with_msg('CRITICAL ERROR! M(salsa20_decrypt): Wrong input type.')

    # Separate nonce from ciphertext.
    nonce     = ctext[:24]
    ctext     = ctext[24:]

    # Convert hexadecimal key to bitstring.
    key       = binascii.unhexlify(hex_key)

    # Create keystream and XOR ciphertext with it to obtain plaintext.
    plaintext = XSalsa20_xor(ctext, nonce, key)

    return plaintext


def self_test_salsa20():
    """
    Run salsa20 self test.

    :return: None.
    """

    print 'Salsa20     self test initializated'
    test_pt  = 'Salsa20 initialization test'
    test_key = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    test_ct  = salsa20_encrypt(test_pt, test_key)
    dec_pt   = salsa20_decrypt(test_ct, test_key)

    if test_pt != dec_pt:
        exit_with_msg('CRITICAL ERROR! Salsa20 self test failed.')
    else:
        print 'Salsa20     self test successful'
        return None


# Twofish CTR
def twofish_encrypt(plaintext, hex_key):
    """
    Encrypt plaintext with Twofish in CTR mode.

    :param plaintext: Input to be encrypted.
    :param hex_key:   Independent 256-bit encryption key.
    :return:          Twofish ciphertext.

    Twofish is based on well understood Feistel network, but since the
    implementation used is ECB mode, a custom CTR-mode was created:

    'Plaintext' is padded to 16 byte blocks. Next, a 128-bit nonce is loaded
    from /dev/urandom. For each 'plaintext' block, the nonce is XORred with
    an increasing counter to create an IV, that is then encrypted with Twofish
    using a 256-bit symmetric key to produce a key stream block. Once the key
    stream is as long as the 'plaintext', the two are XORred together to
    produce the ciphertext. Finally, the nonce is appended to the ciphertext.

    The difference to standard version is, separate space for counter is not
    reserved: this allows the IV more entropy compared to concatenated 64-bit
    nonce and 64-bit counters.
    """

    # Verify input parameter types.
    if not (isinstance(plaintext, str) and isinstance(hex_key, str)):
        exit_with_msg('CRITICAL ERROR! M(twofish_encrypt): Wrong input type.')

    # Add padding to plaintext.
    length     = 16 - (len(plaintext) % 16)
    plaintext += length * chr(length)

    # Convert hexadecimal key to binary data.
    key        = binascii.unhexlify(hex_key)

    # Generate a 128-bit nonce.
    nonce      = os.urandom(16)

    # n.o. keystream blocks equals the n.o. plaintext blocks.
    msg_a      = [plaintext[i:i + 16] for i in range(0, len(plaintext), 16)]

    keystream  = ''
    counter    = 1
    i          = 0
    iv_list    = []

    while i < len(msg_a):

        # Prepend counter with zeros.
        ctr = str(counter).zfill(16)

        iv  = ''

        # XOR 128-bit nonce with the counter to create IV of Twofish cipher.
        if len(ctr) == 16 and len(nonce) == 16:
            iv = ''.join(chr(ord(c) ^ ord(n)) for c, n in zip(ctr, nonce))
        else:
            exit_with_msg('CRITICAL ERROR! M(twofish_encrypt): Twofish counter hash - nonce length mismatch.')

        # Check IV was not already used.
        if iv in iv_list:
            exit_with_msg('CRITICAL ERROR! M(twofish_encrypt): Twofish IV was used twice.')
        else:
            iv_list.append(iv)

        # Initialize Twofish cipher with key.
        twofish    = Twofish(key)

        # Encrypt the unique IV with key.
        key_block  = twofish.encrypt(iv)

        # Append new block to keystream.
        keystream += key_block

        # Increase the counter of randomized CTR mode.
        counter   += 1

        i += 1

    # Double-check IV is not used twice.
    try:
        seen = set()
        assert not any(i in seen or seen.add(i) for i in iv_list)

    except AssertionError:
        exit_with_msg('CRITICAL ERROR! M(twofish_encrypt): Twofish IV was used twice.')

    ciphertext = ''

    # XOR keystream with plaintext to acquire ciphertext.
    if len(plaintext) == len(keystream):
        ciphertext = ''.join(chr(ord(p) ^ ord(k)) for p, k in zip(plaintext, keystream))
    else:
        exit_with_msg('CRITICAL ERROR! M(twofish_encrypt): Twofish plaintext - keystream length mismatch.')

    return nonce + ciphertext


def twofish_decrypt(ctext, hex_key):
    """
    Decrypt ciphertext with Twofish in CTR mode. (Used in Tx.py for self testing.)

    :param ctext:   Encrypted test string.
    :param hex_key: 256-bit self-test encryption key.
    :return:        Plaintext to be compared.

    Twofish is based on well understood Feistel network. Since the
    library provided by Keystream is ECB mode, a custom CTR-mode was created:

    Nonce is separated from ciphertext that is then padded to 16 byte blocks.
    Next, for each ciphertext block, the nonce is XORred a counter to create
    an IV, that is then encrypted with Twofish using an independent 256-bit
    symmetric key to produce a key stream block. Once the key stream is as
    long as the ciphertext, the two are XORred together to produce the plaintext.
    In last step the padding is removed from the obtained plaintext.
    """

    # Verify input parameter types.
    if not (isinstance(ctext, str) and isinstance(hex_key, str)):
        exit_with_msg('CRITICAL ERROR! M(twofish_decrypt): Wrong input type.')

    # Separate nonce from ciphertext.
    nonce     = ctext[:16]
    ctext     = ctext[16:]

    # Convert hexadecimal key to binary data.
    key       = binascii.unhexlify(hex_key)

    # n.o. keystream blocks equals the n.o. ctext blocks.
    ct_array  = [ctext[i:i + 16] for i in range(0, len(ctext), 16)]

    keystream = ''
    counter   = 1
    i         = 0
    iv_list   = []

    while i < len(ct_array):

        # Prepend counter with zeros.
        ctr = str(counter).zfill(16)

        iv  = ''

        # XOR 128-bit nonce with the counter to create IV of Twofish cipher.
        if len(ctr) == 16 and len(nonce) == 16:
            iv = ''.join(chr(ord(c) ^ ord(n)) for c, n in zip(ctr, nonce))
        else:
            exit_with_msg('CRITICAL ERROR! M(twofish_decrypt): Twofish counter hash - nonce length mismatch.')

        # Check IV was not already used.
        if iv in iv_list:
            exit_with_msg('CRITICAL ERROR! M(twofish_decrypt): Twofish IV was used twice.')
        else:
            iv_list.append(iv)

        # Initialize Twofish cipher with key.
        twofish    = Twofish(key)

        # Encrypt unique IV with key.
        key_block  = twofish.encrypt(iv)

        # Append new block to keystream.
        keystream += key_block

        # Increase the counter of randomized CTR mode.
        counter   += 1

        i += 1

    # Double check IV is not used twice.
    try:
        seen = set()
        assert not any(i in seen or seen.add(i) for i in iv_list)

    except AssertionError:
        exit_with_msg('CRITICAL ERROR! M(twofish_decrypt): Twofish IV was used twice.')

    plaintext = ''

    # XOR keystream with ciphertext to acquire plaintext.
    if len(ctext) == len(keystream):
        plaintext = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(ctext, keystream))
    else:
        exit_with_msg('CRITICAL ERROR! M(twofish_decrypt): Twofish ciphertext - keystream length mismatch.')

    # Remove padding.
    plaintext = plaintext[:-ord(plaintext[-1:])]

    return plaintext


def self_test_twofish_ctr():
    """
    Run Twofish CTR mode self test.

    :return: None.
    """

    print 'Twofish-CTR self test initializated'
    test_pt  = 'Twofish CTR initialization test'
    test_key = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    test_ct  = twofish_encrypt(test_pt, test_key)
    dec_pt   = twofish_decrypt(test_ct, test_key)

    if test_pt != dec_pt:
        exit_with_msg('CRITICAL ERROR! Twofish CTR self test failed.')
    else:
        print 'Twofish-CTR self test successful'
        return None


# AES-GCM
def aes_gcm_encrypt(plaintext, hex_key):
    """
    Encrypt plaintext with AES in GCM mode.

    :param plaintext: Input to be encrypted.
    :param hex_key:   Independent 256-bit encryption key.
    :return:          AES ciphertext.

    AES in GCM mode is used as the outermost encryption layer
    as it provides integrity for previous layers of cascaded
    encryption.

    GCM-mode AES allows encryption of up to 2^39 bits of plaintext
    for each IV-key pair. The standard length for 'plaintext' is
    1920 bits. The AES implementation uses a 256-bit symmetric key
    together with 512-bit IV that is loaded from /dev/urandom.
    """

    # Verify input parameter types.
    if not (isinstance(plaintext, str) and isinstance(hex_key, str)):
        exit_with_msg('CRITICAL ERROR! M(aes_gcm_encrypt): Wrong input type.')

    # Convert hex key to binary format.
    key        = binascii.unhexlify(hex_key)

    # Generate a 512 bit nonce.
    nonce      = os.urandom(64)

    # Initialize cipher.
    cipher     = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update('')

    # Encrypt the plaintext.
    ct_list    = nonce, cipher.encrypt(plaintext), cipher.digest()

    # Convert ciphertext list to string.
    ciphertext = ''.join(ct_list)

    return ciphertext


def aes_gcm_decrypt(ctext, hex_key):
    """
    Decrypt and authenticate ciphertext with AES in GCM mode. (Used in Tx.py for self testing.)

    :param ctext:   Encrypted test string.
    :param hex_key: 256-bit self-test encryption key.
    :return:        Plaintext to be compared.
    """

    # Verify input parameter types.
    if not (isinstance(ctext, str) and isinstance(hex_key, str)):
        exit_with_msg('CRITICAL ERROR! M(aes_gcm_decrypt): Wrong input type.')

    nonce      = ctext[:64]
    ciphertext = ctext[64:-16]
    mac        = ctext[-16:]
    aes_key    = binascii.unhexlify(hex_key)

    # Initialize cipher.
    cipher     = AES.new(aes_key, AES.MODE_GCM, nonce)
    cipher.update('')

    # Decrypt the ciphertext.
    plaintext  = cipher.decrypt(ciphertext)

    # Verify the MAC.
    try:
        cipher.verify(mac)
        return plaintext

    except ValueError:
        return 'MAC_FAILED'

    except TypeError:
        return 'MAC_FAILED'


def self_Test_aes_gcm():
    """
    Run AES GCM mode self test.

    :return: None.
    """

    print 'AES_GCM     self test initializated'
    test_pt  = 'AES_GCM initialization test'
    test_key = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    test_ct  = aes_gcm_encrypt(test_pt, test_key)
    dec_pt   = aes_gcm_decrypt(test_ct, test_key)

    if dec_pt == 'MAC_FAILED':
        exit_with_msg('CRITICAL ERROR! AES_GCM (authentication) self test failed.')

    if test_pt != dec_pt:
        exit_with_msg('CRITICAL ERROR! AES_GCM (encryption) self test failed.')
    else:
        print 'AES_GCM     self test successful'
        return None


# Cascading encryption.
def quad_encrypt(xmpp, pt):
    """
    Encrypt plaintext with set of ciphers.

    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :param pt:   Plaintext message to be encrypted.
    :return:     The outermost ciphertext and it's nonce.

    Symmetric algorithms have not been proven secure. Based on the
    recommendations of the technical community including E. Snowden*,
    the symmetric encryption version uses a set of symmetric ciphers
    with different internal structures. This way the attacker would
    need to have attacks against several cryptographic primitives.

    * https://www.youtube.com/watch?v=7Ui3tLbzIgQ#t=12m40s

    Each cipher uses an independent 256-bit symmetric key yielding a
    total of 1024 bits of security, while at the same time providing
    perfect forward secrecy: By hashing the used encryption key with
    Keccak-256 (SHA3) immediately after use, previous key is deleted.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(pt, str)):
        exit_with_msg('CRITICAL ERROR! M(encrypt): Wrong input type.')

    # Load key set.
    k_s = get_keyset(xmpp)

    # Encrypt the plaintext.
    ct1 = keccak_encrypt(pt, k_s[0])
    ct2 = salsa20_encrypt(ct1, k_s[1])
    ct3 = twofish_encrypt(ct2, k_s[2])
    ct4 = aes_gcm_encrypt(ct3, k_s[3])

    rotate_keyset(xmpp)

    return ct4


# TFC-CEV self testing.
def tfc_cev_self_test():
    """
    Run TFC encryption self tests.

    :return: None.

    Test each Keccak hash function and all encryption implementations
    to detect errors in libraries / methods. Exit gracefully in case
    errors occur.
    """

    os.system('clear')
    print 'TFC-CEV %s || Tx.py || Running self tests...\n' % version

    # Run self tests.
    self_test_keccak_ctr()
    self_test_salsa20()
    self_test_twofish_ctr()
    self_Test_aes_gcm()

    print '\nAll tests successful.\n'
    time.sleep(0.5)
    os.system('clear')

    return None


def rotate_keyset(xmpp):
    """
    Rotate next set of keys by replacing the key with it's Keccak256 digest.
    This operation removes previous keys providing perfect forward secrecy.

    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :return:     None.
    """

    # Verify input parameter type.
    if not isinstance(xmpp, str):
        exit_with_msg('CRITICAL ERROR! M(rotate_keyset): Wrong input type.')

    keyset   = get_keyset(xmpp, output=False)
    new_keys = []

    try:
        with open('tx.' + xmpp + '.e', 'w+') as f:
            for key in keyset:
                new_key = keccak256(key)
                new_keys.append(new_key)
                f.write(new_key + '\n')

    except IOError:
        exit_with_msg("CRITICAL ERROR! M(rotate_keyset): Keyfile 'tx.%s.e' could not be loaded" % xmpp)

    # Print list of written keys (for debugging purposes).
    if debugging:
        print "\nM(rotate_keyset): Wrote following keys to keyfile 'tx.%s.e':\n" % xmpp
        for key in new_keys:
            print key
        print '\n'

    # Verify that keys were successfully written.
    if new_keys != get_keyset(xmpp, output=False):
        exit_with_msg('CRITICAL ERROR! M(rotate_keyset): Next keyset was not properly stored.')

    if debugging:
        print '\nM(rotate_keyset): Key overwriting successful.\n'

    return None


######################################################################
#                            KEY MANAGEMENT                          #
######################################################################

def get_keyfile_list(local=False):
    """
    Get list of 'tx.xmpp.e' keyfiles in Tx.py directory

    :return: List of keyfiles.
    """

    kf_list  = []

    if local:
        kf_list += [f for f in os.listdir('.') if (f.startswith('tx.') and f.endswith('.e'))]
    else:
        kf_list += [f for f in os.listdir('.') if (f.startswith('tx.') and f.endswith('.e') and f != 'tx.local.e')]

    return kf_list


def search_keyfiles():
    """
    Check that at least one keyfile exists in Tx.py directory.

    :return: None.

    Remove instructions from end of keyfiles.
    Issue a warning if no keyfiles are found.
    """

    # Remove possible instruction from file names.
    for f in os.listdir('.'):
        if f.startswith('tx.') and f.endswith('.e - Move this file to your TxM'):
            os.rename(f, f[:-29])

    # If loaded keyfile list is empty, exit.
    if not get_keyfile_list():
        exit_with_msg('Error: No keyfiles for contacts were found.\nMake sure keyfiles are in same directory as Tx.py.')
    return None


def get_keyset(xmpp, output=True):
    """
    Load set of keys for selected contact.

    :param xmpp:   The contact's XMPP-address (i.e. alice@jabber.org).
    :param output: When output and debugging is True, print encryption keys.
    :return:       The set of three one time keys.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(output, bool)):
        exit_with_msg('CRITICAL ERROR! M(get_keyset): Wrong input type.')

    try:
        keyset = []

        with open('tx.' + xmpp + '.e') as f:
            key_file = f.readlines()

        for line in key_file:
            key = line.strip('\n')

            # Verify keys in keyfile have proper hex-format.
            valid_chars = ['0', '1', '2', '3',
                           '4', '5', '6', '7',
                           '8', '9', 'A', 'B',
                           'C', 'D', 'E', 'F',
                           'a', 'b', 'c', 'd',
                           'e', 'f',]

            for c in key:
                if c not in valid_chars:
                    exit_with_msg("CRITICAL ERROR! M(get_keyset): Illegal character '%s' in keyfile 'tx.%s.e'." % (c, xmpp))

            # Verify keys are of proper length.
            if len(key) != 64:
                exit_with_msg("CRITICAL ERROR! M(get_keyset): Illegal length key in keyfile 'tx.%s.e" % xmpp)
            else:
                keyset.append(key)

    except IOError:
        exit_with_msg("CRITICAL ERROR! M(get_keyset): Failed to open keyfile 'tx.%s.e'" % xmpp)

    # Verify that four keys were loaded.
    if len(keyset) != 4:
        exit_with_msg("CRITICAL ERROR! M(get_keyset): Keyfile 'tx.%s.e' did not contain four keys." % xmpp)

    # Verify that all keys are unique.
    if any(keyset.count(k) > 1 for k in keyset):
        exit_with_msg("CRITICAL ERROR! M(get_keyset): Two or more identical keys in keyfile 'tx.%s.e" % xmpp)

    # Print list of keys (for debugging purposes).
    if debugging and output:
        print "\nM(get_keyset): Loaded following set of keys for XMPP '%s':\n" % xmpp
        for key in keyset:
            print key
        print '\n'

    return keyset


######################################################################
#                           SECURITY RELATED                         #
######################################################################

def chk_pkg_size():
    """
    Due to padding implementation, the max size of packet is 255.
    Due to TFC noise message length, the min size of packet is 15.

    :return: None.
    """

    if pkg_size > 250:
        exit_with_msg("ERROR! Maximum length of packet is 250 characters.\n"
                      "Please fix the value 'pkg_size'and restart TFC.")

    if pkg_size < 15:
        exit_with_msg("ERROR! Minimum length of packet is 25 characters.\n"
                      "Please fix the value 'pkg_size' and restart TFC.")
    return None


def ct_sleep():
    """
    Sleep constant time + jitter to obfuscate
    slight variances in function processing times.

    If random_sleep is enabled, sleep random amount.

    :return: None.
    """

    time.sleep(ct_static_sleep / 2.0)
    time.sleep(random.uniform(jitter_min, jitter_max))

    if random_sleep:
        time.sleep(random.uniform(0, max_sleep_time))

    return None


def exit_with_msg(message):
    """
    Exit Tx.py with message.

    :param message: Message to display when exiting.
    :return:        None.
    """

    # Verify input parameter type.
    if not isinstance(message, str):
        print '\nCRITICAL ERROR! M(exit_with_msg): Wrong input type.\nExiting TFC-CEV.\n'
    else:
        os.system('clear')
        print '\n%s\n\nExiting TFC-CEV.\n\n' % message

    if c_transmission and not local_testing:
        subprocess.Popen('killall python', shell=True).wait()
    else:
        exit()


######################################################################
#                         CONTACT MANAGEMENT                         #
######################################################################

def change_recipient(parameter):
    """
    Change global xmpp and nick variables to change recipient.

    :param parameter: Recipients nick that needs to be separated from command.
    :return:          None.
    """

    # Verify input parameter type.
    if not isinstance(parameter, str):
        exit_with_msg('CRITICAL ERROR! M(change_recipient): Wrong input type.')

    global xmpp
    global nick
    global group

    new_recipient = parameter.split(' ')[1]

    if new_recipient in get_list_of_xmpp_addr():
        xmpp  = new_recipient
        nick  = get_nick(new_recipient)
        group = ''
        os.system('clear')
        print "\nNow sending messages to '%s' (%s)\n" % (nick, new_recipient)
        return None

    elif new_recipient in get_list_of_groups():

        if c_transmission:
            print '\nError: Groups are disabled when constant transmission is enabled.\n'
            time.sleep(1.5)
            return None

        group = new_recipient
        nick  = group
        os.system('clear')
        print "\nNow sending messages to group '%s'\n" % nick
        if not get_group_members(group):
            print 'The selected group is empty.\n'
        return None

    else:
        try:
            xmpp, nick = select_contact(0, new_recipient, False)
            group      = ''
            os.system('clear')
            print "\nNow sending messages to '%s' (%s)\n" % (nick, xmpp)
            return None

        except IndexError:
            print '\nError: Invalid contact / group selection.\n'
            return None

        except ValueError:
            print '\nError: Invalid contact / group selection.\n'
            return None


def get_contact_quantity():
    """
    Get the number of contacts, excludes tx.local.e file if found.

    :return: return number of contacts as an integer.
    """

    i = 0
    try:
        with open('txc.tfc') as f:
            for i, l in enumerate(f):
                pass

            for line in f:
                    if 'local,local,' in line:
                        return i
        return i + 1

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')


def get_list_of_xmpp_addr():
    """
    Get list of available contact XMPP-addresses.

    :return: List of XMPP-addresses.
    """

    xmpp_a_list  = []
    xmpp_a_list += [f[3:][:-2] for f in os.listdir('.') if (f.startswith('tx.') and f.endswith('.e') and f != 'tx.local.e')]

    return xmpp_a_list


def print_contact_list(spacing=False):
    """
    Print list of available contacts and their nicknames.

    :param spacing: When spacing is True, add spacing around the printed table.
    :return:        ID header offset so select_contact() knows where to place caret. OR
                    None for cases when user gives command '/names' to print the list.
    """

    # Verify input parameter type.
    if not isinstance(spacing, bool):
        exit_with_msg('CRITICAL ERROR! M(print_contact_list): Wrong input type.')

    if spacing:
        os.system('clear')
        print ''

    tty_width = get_terminal_width()
    headers   = ['XMPP-address', 'ID', 'Nick']

    xmpp_list = get_list_of_xmpp_addr()
    gap1      = len(max(xmpp_list, key=len)) - len(headers[0]) + 3
    header    = headers[0] + gap1 * ' ' + headers[1] + '  ' + headers[2]
    c_dst     = int(header.index(headers[1][0]))

    print header + '\n' + tty_width * '-'

    for c in xmpp_list:
        sel_id = xmpp_list.index(c)
        nick   = get_nick(c)

        if nick != 'local':
            gap2 = int(header.index(headers[1][0])) - len(c)
            gap3 = int(header.index(headers[2][0])) - len(c) - gap2 - len(str(sel_id))
            print c + gap2 * ' ' + str(sel_id) + gap3 * ' ' + nick

    print '\n'

    if spacing:
        print ''
        return None

    else:
        return c_dst


def select_contact(caret_dist=0, contact_no='', menu=True):
    """
    Select contact to send messages to.

    :param caret_dist: Location of caret when choosing contact.
    :param contact_no: Contact selection number.
    :param menu:       When true, display menu.
    :return:           XMPP-address and nickname.
    """

    # Verify input parameter types.
    if not (isinstance(caret_dist, (int, long)) and isinstance(contact_no, str) and isinstance(menu, bool)):
        exit_with_msg('CRITICAL ERROR! M(select_contact): Wrong input type.')

    c_selected = False
    xmpp       = ''
    nick       = ''

    while not c_selected:
        try:
            # If no parameter about contact selection
            # is passed to function, ask for input.
            if contact_no == '':
                selection  = raw_input('Select contact:' + (caret_dist - 15) * ' ')

                # If user enters xmpp instead of ID, select using it.
                selection  = ' '.join(selection.split())

                if selection in get_list_of_xmpp_addr():
                    nick = get_nick(selection)
                    return selection, nick

                int_selection = int(selection)
            else:
                int_selection = int(contact_no)

        # Error handling if selection was not a number.
        except ValueError:
            if menu:
                os.system('clear')
                print "TFC-CEV %s || Tx.py\n\nError: Invalid selection '%s'\n" % (version, selection)
                print_contact_list()
                continue
            else:
                raise ValueError('Invalid number')

        # Clean exit.
        except KeyboardInterrupt:
            exit_with_msg('')

        # Check that integer is within allowed bounds.
        if (int_selection < 0) or (int_selection > get_contact_quantity()):
            if menu:
                os.system('clear')
                print "TFC-CEV %s || Tx.py\n\nError: Invalid selection '%s'\n" % (version, selection)
                print_contact_list()
                continue
            else:
                raise ValueError('Invalid number')

        # Check that selction number was valid.
        try:
            xmpp = get_list_of_xmpp_addr()[int_selection]
        except IndexError:
            if menu:
                os.system('clear')
                print "TFC-CEV %s || Tx.py\n\nError: Invalid selection '%s'\n" % (version, selection)
                print_contact_list()
                continue
            else:
                print '\nError: Invalid contact selection\n'

        nick = get_nick(xmpp)

        # Check that user has not selected local contact.
        if xmpp == 'local':
            if menu:
                contact_no = ''
                os.system('clear')
                print "TFC-CEV %s || Tx.py\n\nError: Invalid selection '%s'\n" % (version, selection)
                print_contact_list()
                continue
            else:
                raise ValueError('Invalid number')

        c_selected = True

    return xmpp, nick


def get_list_of_targets():
    """
    Targets are the labels to witch messages
    are sent to: Nicknames and group names.

    :return: List of targets.
    """

    nick_list = []
    for i in get_list_of_xmpp_addr():
        nick_list.append(get_nick(i))

    for n in get_list_of_groups():
        nick_list.append(n)

    return nick_list


# txc.tfc MANAGEMENT
def add_contact(nick, xmpp):
    """
    Add new contact to txc.tfc.

    :param nick: Nick of new contact.
    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :return:     None.

    Contacts are stored in CSV file. Each contact has it's own
    line, and settings are stored as [nick, XMPP-addr, keyID].
    """

    # Verify input parameter types.
    if not (isinstance(nick, str) and isinstance(xmpp, str)):
        exit_with_msg('CRITICAL ERROR! M(add_contact): Wrong input type.')

    try:
        with open('txc.tfc', 'a+') as f:
                f.write('%s,%s,1\n' % (nick, xmpp))

    except IOError:
        exit_with_msg('ERROR! M(add_contact): txc.tfc could not be loaded.')

    if debugging:
        print '\nM(add_contact): Added contact %s (XMPP-addr = %s) to txc.tfc.\n' % (nick, xmpp)

    return None


def add_keyfiles():
    """
    Prompt nick names for new contacts / keyfiles and store them to txc.tfc.

    :return: None.
    """

    c_list = []

    try:
        with open('txc.tfc', 'a+') as f:
            for row in csv.reader(f):
                c_list.append(row)

    except IOError:
        exit_with_msg('ERROR! txc.tfc could not be loaded.')

    for kf in get_keyfile_list(local=True):
        existing = False
        xmpp     = kf[3:][:-2]

        for c in c_list:
            if xmpp in c[1]:
                existing = True

        if not existing:

            if xmpp == 'local':
                add_contact('local', 'local')

            else:
                os.system('clear')
                print "TFC-CEV %s || Tx.py\n\nNew contact '%s' found." % (version, xmpp)

                auto_nick = xmpp.split('@')[0]                    # Parse account name.
                auto_nick = auto_nick[0].upper() + auto_nick[1:]  # Capitalize.
                nick      = ''

                try:
                    nick = raw_input("\nGive nickname to contact or press enter to use '%s' as nick: " % auto_nick)
                except KeyboardInterrupt:
                    exit_with_msg('')

                if nick == '':
                    nick = auto_nick

                if nick in get_list_of_groups():
                    print 'Error: Group with same name alread exists.'
                    nick = ''

                add_contact(nick, xmpp)

    return None


def get_key_id(xmpp):
    """
    Get key ID for XMPP-contact.

    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :return:     The key ID (integer).

    The loaded key ID is the counter that defines the number of times keys need
    to be iterated through Keccak to produce current key. key_id is increased
    by one after every encrypted message and the old key is destroyed.
    """

    # Verify input parameter type.
    if not isinstance(xmpp, str):
        exit_with_msg('CRITICAL ERROR! M(get_key_id): Wrong input type.')

    try:
        c_list = []
        key_id = 0

        with open('txc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

        for i in range(len(c_list)):
            if c_list[i][1] == xmpp:
                key_id = int(c_list[i][2])

        # Verify key_id is positive.
        if key_id > 0:
            return key_id
        else:
            exit_with_msg("ERROR! M(get_key_id): Failed to load valid key_id for contact '%s'." % xmpp)

    except ValueError:
        exit_with_msg(    "ERROR! M(get_key_id): Failed to load valid key_id for contact '%s'." % xmpp)

    except IOError:
        exit_with_msg(    'ERROR! M(get_key_id): txc.tfc could not be loaded.')


def get_nick(xmpp):
    """
    Load nick from txc.tfc.

    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :return:     The nickname for specified XMPP.
    """

    # Verify input parameter type.
    if not isinstance(xmpp, str):
        exit_with_msg('CRITICAL ERROR! M(get_nick): Wrong input type.')

    c_list = []

    try:
        with open('txc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

    except IOError:
        exit_with_msg('ERROR! M(get_nick): txc.tfc could not be loaded.')

    for i in range(len(c_list)):
        if c_list[i][1] == xmpp:
            nick = c_list[i][0]

            return nick

    exit_with_msg("ERROR! M(get_nick): Failed to load nick for contact '%s'." % xmpp)


def write_key_id(xmpp, keyid):
    """
    Write new key ID for contact to txc.tfc.

    :param xmpp:  The contact's XMPP-address (i.e. alice@jabber.org).
    :param keyid: The counter of message, defines the offset in keyfile.
    :return:      None.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(keyid, (int, long))):
        exit_with_msg('CRITICAL ERROR! M(write_key_id): Wrong input type.')

    try:
        c_list = []

        with open('txc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

        xmpp_found = False

        for i in range(len(c_list)):
            if c_list[i][1] == xmpp:
                xmpp_found   = True
                c_list[i][2] = keyid

        if not xmpp_found:
            exit_with_msg("ERROR! M(write_key_id): Could not find contact '%s' from txc.tfc." % xmpp)

        with open('txc.tfc', 'w') as f:
            csv.writer(f).writerows(c_list)

    except IOError:
        exit_with_msg('ERROR! M(write_key_id): txc.tfc could not be loaded.')

        # Verify key_id has been properly written.
        new_stored_key = get_key_id(xmpp)
        if keyid != new_stored_key:
            exit_with_msg("CRITICAL ERROR! M(write_key_id): KeyID for contact '%s' was not properly stored to txc.tfc." % xmpp)

        if debugging:
            print "\nM(write_key_id): Wrote key ID '%s' for contact %s to txc.tfc\n" % (str(keyid), xmpp)

    return None


def write_nick(xmpp, nick):
    """
    Write new nick for contact to txc.tfc.

    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :param nick: New nick for contact.
    :return:     None.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(nick, str)):
        exit_with_msg('CRITICAL ERROR! M(write_nick): Wrong input type.')

    try:
        c_list = []

        with open('txc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

        nick_changed = False

        for i in range(len(c_list)):
            if c_list[i][1] == xmpp:
                c_list[i][0] = nick
                nick_changed = True

        if not nick_changed:
            exit_with_msg("ERROR! M(write_nick): Could not find contact '%s' from txc.tfc." % xmpp)

        with open('txc.tfc', 'w') as f:
            csv.writer(f).writerows(c_list)

        if debugging:
            print "\nM(write_nick): Wrote nick '%s' for account '%s' to txc.tfc\n" % (nick, xmpp)

    except IOError:
        exit_with_msg('ERROR! M(write_nick): txc.tfc could not be loaded.')

    return None


######################################################################
#                           MSG PROCESSING                           #
######################################################################

def base64_encode(content):
    """
    Encode string to base64.

    :param content: String to be encoded.
    :return:        Encoded string.
    """

    # Verify input parameter type.
    if not isinstance(content, str):
        exit_with_msg('CRITICAL ERROR! M(base64_encode): Wrong input type.')

    return base64.b64encode(content)


def crc32(content):
    """
    Calculate CRC32 checksum of input.

    :param content: Input checksum is calculated from.
    :return:        CRC32 checksum of input.
    """

    # Verify input parameter type.
    if not isinstance(content, str):
        exit_with_msg('CRITICAL ERROR! M(crc32): Wrong input type.')

    return str(hex(zlib.crc32(content)))


def long_msg_preprocess(payload):
    """
    Prepare long messages for transmission in multiple parts.

    :param payload: Long message to be transmitted in multiple parts.
    :return:        Plaintext in array of 'pkgSize' sized packets.
    """

    # Verify input parameter type.
    if not isinstance(payload, str):
        exit_with_msg('CRITICAL ERROR! M(long_msg_preprocess): Wrong input type.')

    type_file = False
    type_mesg = False

    # Determine packet type:
    if payload.startswith('m'):
        type_mesg = True
    elif payload.startswith('f'):
        type_file = True
    else:
        exit_with_msg('CRITICAL ERROR! M(long_msg_preprocess): Unknown packet type detected.')

    # Remove the {m,f} header and new lines.
    payload = payload[1:].strip('\n')

    # Strip leading white space.
    while payload.startswith(' '):
        payload = payload[1:]

    # Append Keccak256 hash of message / file to packet.
    str_hash = keccak256(payload)
    payload += str_hash

    # Split packet to list the items of which are 3 char shorter than max length:
    # This leaves room for 2 char header and prevents dummy blocks when padding.
    packet_a = [payload[i:i + (pkg_size - 3)] for i in range(0, len(payload), (pkg_size - 3))]

    if type_mesg:                                  # All packets have header {s,l,a,e}{m,f}.
        for i in xrange(len(packet_a)):
            packet_a[i] = 'am' + packet_a[i]       # 'am' = appended message packets.
        packet_a[-1]    = 'em' + packet_a[-1][2:]  # 'em' = end message packets.
        packet_a[0]     = 'lm' + packet_a[0][2:]   # 'lm' = start of long message packets.

    if type_file:
        for i in xrange(len(packet_a)):
            packet_a[i] = 'af' + packet_a[i]       # 'af' = appended file packets.
        packet_a[-1]    = 'ef' + packet_a[-1][2:]  # 'ef' = end file packets.
        packet_a[0]     = 'lf' + packet_a[0][2:]   # 'lf' = start of long file packets.

    if debugging:
        print '\nM(long_msg_preprocess): Processed long message to following packets:'
        for item in packet_a:
            print "'%s'\n" % item

    return packet_a


def padding(string):
    """
    Padd input to always match the pkg_size.

    :param string: String to be padded.
    :return:       Padded string.

    Byte used in padding is determined by how much padding is needed.
    """

    # Verify input parameter type.
    if not isinstance(string, str):
        exit_with_msg('CRITICAL ERROR! M(padding): Wrong input type.')

    length  = pkg_size - (len(string) % pkg_size)
    string += length * chr(length)

    if debugging:
        print '\nM(padding): Padded input to length of %s chars:\n"%s"\n' % (str(len(string)), string)

    return string


######################################################################
#                          ENCRYPTED COMMANDS                        #
######################################################################


def change_logging(parameters):
    """
    Send packet to Rx.py to enable / disable logging.

    :param parameters: Command with it's parameters.
    :return:           None.
    """

    # Verify input parameter type.
    if not isinstance(parameters, str):
        exit_with_msg('CRITICAL ERROR! M(change_logging): Wrong input type.')

    # Check that local keyfile exists.
    if not os.path.isfile('tx.local.e'):
        print "\nError: Keyfile 'tx.local.e' was not found. Command was not sent.\n"

    else:
        parameters = ' '.join(parameters.split())
        value      = str(parameters.split(' ')[1])

        if value   == 'on':
            command_transmit('LOGSON')
        elif value == 'off':
            command_transmit('LOGSOFF')
        else:
            print '\nError: Invalid command.\n'

        return None


def change_nick(xmpp, parameters):
    """
    Change global variable nick name to specified.

    :param xmpp:       Target XMPP the nick of which is changed.
    :param parameters: New nick name yet to be separated from command.
    :return:           None.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(parameters, str)):
        exit_with_msg('CRITICAL ERROR! M(change_nick): Wrong input type.')

    # Check that local keyfile exists.
    if not os.path.isfile('tx.local.e'):
        print "\nError: Keyfile 'tx.local.e' was not found. Command was not sent.\n"
        return None

    parameters = ' '.join(parameters.split())
    new_nick   = parameters.split(' ')[1]

    if group:
        print "\nError: Group is selected. Can't change nick.\n"
        return None

    global nick

    # Check that specified nick is acceptable.
    if new_nick == '':
        print "\nError: Can't give empty nick.\n"

    elif new_nick == 'local':
        print "\nError: Can't give local keyfile name as nick.\n"

    elif '=' in new_nick or '/' in new_nick:
        print "\nError: Nick can't not contain characters '/' or '='.\n"

    elif new_nick in get_list_of_groups():
        print '\nGroup is selected, no nick was changed.\n'

    elif new_nick in get_list_of_xmpp_addr():
        print "\nError: Nick can't be an XMPP-address.\n"

    else:
        write_nick(xmpp, new_nick)
        nick    = get_nick(xmpp)

        os.system('clear')
        command_transmit('NICK me.%s %s'  % (xmpp, nick))
        print '\nChanged %s nick to %s\n' % (xmpp, nick)

    return None


def clear_screens(xmpp):
    """
    Send clear screen to NH.py, Pidgin and Rx.py.

    If constant transmission is enabled, send
    encrypted clear screen command to Rx.py

    :param xmpp: Target to clear pidgin screen from.
    :return:     None.
    """

    # Verify input parameter type.
    if not isinstance(xmpp, str):
        exit_with_msg('CRITICAL ERROR! M(clear_screens): Wrong input type.')

    if c_transmission:
        # Check that local keyfile exists.
        if not os.path.isfile('tx.local.e'):
            print "\nError: Keyfile 'tx.local.e' was not found. Command was not sent.\n"
            return None

    if local_testing:
        if c_transmission:
            command_transmit('CLEARSCREEN')
        else:
            with open('TxOutput', 'w+') as f:
                f.write('CLEARSCREEN ' + xmpp + '\n')

    else:
        if c_transmission:
            command_transmit('CLEARSCREEN')
        else:
            port.write('CLEARSCREEN ' + xmpp + '\n')

    os.system('clear')

    return None


def save_file(parameters):
    """
    Command Rx.py to store tmp keyfile as specified output name and file extension.

    :param parameters: Temporary file name and final file name / reject command.
    :return:           None.
    """

    # Verify input parameter type.
    if not isinstance(parameters, str):
        exit_with_msg('CRITICAL ERROR! M(save_file): Wrong input type.')

    # Check that local keyfile exists.
    if not os.path.isfile('tx.local.e'):
        print "\nError: Keyfile 'tx.local.e' was not found. Command was not sent.\n"

    params = parameters.split(' ')

    if params[1] == 'list':
        command_transmit('STOREFILE PRINT LIST')
        return None

    try:
        command_transmit('STOREFILE %s %s' % (str(params[1]), str(params[2])))

    except IndexError:
        print '\nError: Invalid command.\n'

    return None


######################################################################
#                COMMAND / MESSAGE / FILE TRANSMISSION               #
######################################################################

def command_transmit(command):
    """
    Send commands to RxM via RS232 interface.

    :param command: The plaintext command.
    :return:        None.
    """

    # Verify input parameter type.
    if not isinstance(command, str):
        exit_with_msg('CRITICAL ERROR! M(command_transmit): Wrong input type.')

    key_id      = get_key_id('local')

    padded_cmd  = padding(command)
    ct_with_tag = quad_encrypt('local', padded_cmd)

    encoded     = base64_encode(ct_with_tag)
    checksum    = crc32(encoded + '|' + str(key_id))

    write_key_id('local', key_id + 1)
    command_output(encoded, key_id, checksum)

    return None


def command_output(ct, keyid, crc):
    """
    Output command packet to RS232 interface.

    :param ct:    Ciphertext and MAC of mcd in base64 format.
    :param keyid: KeyID appended to packet.
    :param crc:   CRC32 detects transmission errors over RS232 data diode.
    :return:      None.
    """

    # Verify input parameter types.
    if not (isinstance(ct, str) and isinstance(keyid, (int, long)) and isinstance(crc, str)):
        exit_with_msg('CRITICAL ERROR! M(command_output): Wrong input type.')

    cmd_packet = '<ctrl>%s|%s~%s\n' % (ct, str(keyid), crc)

    if local_testing:
        with open('TxOutput', 'w+') as f:
            f.write(cmd_packet)
        if debugging:
            print '\nM(command_output): Cmd to NH:\n%s\n' % cmd_packet

    else:
        port.write(cmd_packet)
        if debugging:
            print '\nM(command_output): Cmd to NH:\n%s\n' % cmd_packet

    return None


def long_msg_transmit(plaintext, xmpp):
    """
    Send long messages via RS232 interface.

    :param plaintext: Long plaintext message.
    :param xmpp:      The contact's XMPP-address (i.e. alice@jabber.org).
    :return:          None.
    """

    # Verify input parameter types.
    if not (isinstance(plaintext, str) and isinstance(xmpp, str)):
        exit_with_msg('CRITICAL ERROR! M(long_msg_transmit): Wrong input type.')

    packet_list = long_msg_preprocess(plaintext)

    if plaintext.startswith('f'):
        print '\nTransferring file over %s packets. ^C cancels.'    % str(len(packet_list))
    if plaintext.startswith('m'):
        print '\nTransferring message over %s packets. ^C cancels.' % str(len(packet_list))

    for packet in packet_list:
        try:
            key_id      = get_key_id(xmpp)

            padded_msg  = padding(packet)
            ct_with_tag = quad_encrypt(xmpp, padded_msg)

            encoded     = base64_encode(ct_with_tag)
            checksum    = crc32(encoded + '|' + str(key_id))

            write_key_id(xmpp, key_id + 1)
            message_output(xmpp, encoded, key_id, checksum)

            # When transmitting long packets, send a noise
            # command between packets with ~1/2 probability.
            if c_transmission:
                ct_sleep()
                if ord(os.urandom(1)) % 2 == 1:
                    command_transmit('TFCNOISECOMMAND')
                    ct_sleep()

            else:
                if random_sleep:
                    sleep_time = random.uniform(0, max_sleep_time)
                    print 'Sleeping %s seconds to obfuscate long message.' % str(sleep_time)
                    time.sleep(sleep_time)

                # Minimum sleep time ensures XMPP server is not flooded.
                time.sleep(l_msg_sleep)

        except KeyboardInterrupt:

            # If user interrupts packet transmission,
            # send encrypted notification to contact.
            if plaintext.startswith('f'):
                print '\nFile transmission interrupted by user.\n'
                cancel_msg = 'cf'
            else:
                print '\nMessage transmission interrupted by user.\n'
                cancel_msg = 'cm'

            key_id      = get_key_id(xmpp)

            padded_msg  = padding(cancel_msg)
            ct_with_tag = quad_encrypt(xmpp, padded_msg)

            encoded     = base64_encode(ct_with_tag)
            checksum    = crc32(encoded + '|' + str(key_id))

            write_key_id(xmpp, key_id + 1)
            message_output(xmpp, encoded, key_id, checksum)

            # When transmitting the notification, also send a noise
            # command after the packet packet with ~1/2 probability.
            if c_transmission:
                if ord(os.urandom(1)) % 2 == 1:
                    command_transmit('TFCNOISECOMMAND')
                    ct_sleep()

            return None

    if plaintext.startswith('f'):
        print '\nFile transmission complete.\n'
    if plaintext.startswith('m'):
        print '\nMessage transmission complete.\n'

    return None


def short_msg_transmit(plaintext, xmpp):
    """
    Send short messages via RS232 interface.

    :param plaintext: Short plaintext message.
    :param xmpp:      The contact's XMPP-address (i.e. alice@jabber.org).
    :return:          None.
    """

    # Verify input parameter types.
    if not (isinstance(plaintext, str) and isinstance(xmpp, str)):
        exit_with_msg('CRITICAL ERROR! M(short_msg_transmit): Wrong input type.')



    key_id      = get_key_id(xmpp)

    padded_msg  = padding('s' + plaintext)  # 's' = single packet msg.

    ct_with_tag = quad_encrypt(xmpp, padded_msg)

    encoded     = base64_encode(ct_with_tag)
    checksum    = crc32(encoded + '|' + str(key_id))

    write_key_id(xmpp, key_id + 1)
    message_output(xmpp, encoded, key_id, checksum)

    return None


def message_output(xmpp, ct, keyid, crc):
    """
    Output message to RS232 interface.

    :param xmpp:  The contact's XMPP-address (i.e. alice@jabber.org).
    :param ct:    Ciphertext and MAC of msg in base64 format.
    :param keyid: KeyID appended to packet.
    :param crc:   CRC32 detects transmission errors over RS232 data diode.
    :return:      None.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(ct, str) and isinstance(keyid, (int, long)) and isinstance(crc, str)):
        exit_with_msg('CRITICAL ERROR! M(message_output): Wrong input type.')

    msg_packet = '<mesg>%s~?TFC_%s|%s~%s\n' % (xmpp, ct, str(keyid), crc)

    if local_testing:
        with open('TxOutput', 'w+') as f:
            f.write(msg_packet)
        if debugging:
            print '\nM(message_output): Msg to NH:\n' + msg_packet

    else:
        port.write(msg_packet)
        if debugging:
            print '\nM(message_output): Msg to NH:\n' + msg_packet

    return None


def quit_process(output=False):
    """
    Broadcast quit command to NH and RxM.

    :param output: Output notification about exiting.
    :return:       None.
    """

    # Verify input parameter type.
    if not isinstance(output, bool):
        exit_with_msg('CRITICAL ERROR! M(quit_process): Wrong input type.')

    os.system('clear')

    if output:
        print '\nExiting TFC\n'

    if local_testing:
        with open('TxOutput', 'w+') as f:
            f.write('EXITTFC\n')
    else:
        port.write('EXITTFC\n')
    exit()


def send_msg_or_file(payload):
    """
    Send message or file to one ore contacts.

    :param payload: Message / file content to be sent.
    :return:        None.
    """

    # Verify input parameter type.
    if not isinstance(payload, str):
        exit_with_msg('CRITICAL ERROR! M(send_msg_or_file): Wrong input type.')

    if group:

        group_member_list = get_group_members(group)

        if not group_member_list:
            if payload.startswith('f'):
                print '\nCurrently selected group is empty. No file was sent.\n'
            else:
                print '\nCurrently selected group is empty. No message was sent.\n'
            return None

        # Multicasted messages.
        for member in group_member_list:
            print '           > ' + member

            if len(payload) > pkg_size:
                long_msg_transmit(payload, member)

            else:
                short_msg_transmit(payload, member)
                time.sleep(0.1)
        print ''

    # Standard messages.
    else:
        if len(payload) > pkg_size:
            long_msg_transmit(payload, xmpp)

        else:
            short_msg_transmit(payload, xmpp)

    return None


######################################################################
#                          GROUP MANAGEMENT                          #
######################################################################

def get_group_members(group_name):
    """
    Get members of group.

    :param group_name: Name of group to list members of.
    :return:           List of group memgbers.
    """

    # Verify input parameter type.
    if not (isinstance(group_name, str)):
        exit_with_msg('CRITICAL ERROR! M(get_group_members): Wrong input type.')

    try:
        g_c_list = []

        with open('g.' + group_name + '.tfc') as f:
            for l in f.readlines():
                g_c_list.append(l.strip('\n'))

        return g_c_list

    except IOError:
        exit_with_msg('ERROR! M(get_group_members): Group file g.%s.tfc could not be loaded.' % group_name)


def get_list_of_groups():
    """
    Get list of existing groups.

    :return: List og groups.
    """

    g_file_list  = []
    g_file_list += [f[2:][:-4] for f in os.listdir('.') if (f.startswith('g.') and f.endswith('.tfc'))]

    return g_file_list


def group_create(parameters):
    """
    Create new group.

    :param   parameters: Command string to be parsed.
    :return: True if new group was created.
    """

    # Verify input parameter type.
    if not (isinstance(parameters, str)):
        exit_with_msg('CRITICAL ERROR! M(group_create): Wrong input type.')

    try:
        parameters = ' '.join(parameters.split())
        parlist    = parameters.split(' ')
        groupname  = parlist[2]

    except IndexError:
        print '\nError: No group name specified.\n'
        return None

    # Overwrite if group exists or abort creation.
    if os.path.isfile('g.' + groupname + '.tfc'):
        if yes('\nGroup already exists. Overwrite?'):
            pass
        else:
            print '\nGroup creation aborted.\n'
            return None

    # Check that group name is not reserved.
    if groupname == '':
        print "\nError: Group name can't be empty.\n"
        return None
    if groupname in ['create', 'add', 'rm']:
        print "\nError: Group name can't be a command.\n"
        return None
    if ' ' in groupname:
        print "\nError: Group name can't have spaces.\n"
        return None

    for f in get_keyfile_list():
        if groupname in get_nick(f[3:][:-2]):
            print "\nError: Group name can't be nick of contact.\n"
            return None
        if groupname in f[3:][:-2]:
            print "\nError: Group name can't be XMPP-address.\n"
            return None
        if groupname in f[:-2]:
            print "\nError: Group name can't be keyfile.\n"
            return None

    # Initialize groups.
    accepted  = []
    rejected  = []

    c_list    = parlist[3:]
    existing  = get_list_of_xmpp_addr()

    for c in c_list:

        if c in existing and c != 'local':
            accepted.append(c)
        else:
            rejected.append(c)

    with open('g.' + groupname + '.tfc', 'w+') as f:
        if accepted:
            for c in accepted:
                f.write(c + '\n')
            print "\nCreated group '%s' with following members:" % groupname
            for c in accepted:
                print '    ' + c
            print ''

        else:
            f.write('')
            print "\nCreated an empty group '%s'\n" % groupname

    # Alphabetize contacts.
    sort_group(groupname)

    if rejected:
        print "\nFollowing unknown members are not in contacts:"
        for c in rejected:
            print '    ' + c
        print ''

    return None


def group_add_member(parameters):
    """
    Add members to specified group. Create new
    group is specified group doesn't exist.

    :param parameters: Group name and member list yet to be separated.
    :return:           None.
    """

    # Verify input parameter type.
    if not (isinstance(parameters, str)):
        exit_with_msg('CRITICAL ERROR! M(group_add_member): Wrong input type.')

    parameters = ' '.join(parameters.split())
    param_list = parameters.split(' ')
    group_name = param_list[2]
    c_eval_lst = param_list[3:]

    c_add_list = []
    c_unknown  = []

    if not os.path.isfile('g.' + group_name + '.tfc'):
        if yes("\nGroup '%s' was not found. Create new group?" % group_name):
            group_create(parameters)
            return None
        else:
            print '\nGroup creation aborted.\n'
            return None

    contacts = get_list_of_xmpp_addr()

    for c in c_eval_lst:
        if c in contacts and c != 'local':
            c_add_list.append(c)
        else:
            c_unknown.append(c)

    already_in_g_f = []
    c_added        = []

    try:
        with open('g.' + group_name + '.tfc', 'a+') as f:
            for c in c_add_list:
                if c not in get_group_members(group_name):
                    f.write(c + '\n')
                    c_added.append(c)
                else:
                    already_in_g_f.append(c)

    except IOError:
        exit_with_msg('ERROR! M(group_add_member): Group file g.%s.tfc could not be loaded.' % group_name)

    # Alphabetize contacts.
    sort_group(group_name)

    if c_added:
        print '\nAdded following contacts to %s:' % group_name
        for c in c_added:
            print '    ' + c
        print ''

    if already_in_g_f:
        print "\nFollowing contacts were already in group '%s':" % group_name
        for c in already_in_g_f:
            print '    ' + c
        print ''

    if c_unknown:
        print "\nFollowing unknown members are not in contacts:"
        for c in c_unknown:
            print '    ' + c
        print '\n'

    return None


def group_rm_member(parameters):
    """
    Remove specified members from group. If no members
    are specified, overwrite and delete group file.

    :param parameters: Group name and list of contacts to remove.
    :return:           None.
    """

    # Verify input parameter type.
    if not (isinstance(parameters, str)):
        exit_with_msg('CRITICAL ERROR! M(group_rm_member): Wrong input type.')

    parameters = ' '.join(parameters.split())
    param_list = parameters.split(' ')
    group_name = param_list[2]
    c_eval_lst = param_list[3:]

    if not os.path.isfile('g.' + group_name + '.tfc'):
        print '\nError: Group does not exist.\n'
        return None

    if not c_eval_lst:
        if yes("\nNo contacts specified! Remove entire group '%s'?" % group_name):
            while os.path.isfile('g.' + group_name + '.tfc'):
                subprocess.Popen('shred -n 3 -z -u g.' + group_name + '.tfc', shell=True).wait()
            print '\nGroup file %s removed.\n' % group_name
            return None
        else:
            print '\nGroup removal aborted.\n'
            return None

    c_rm_list = []
    c_unknown = []
    c_removed = []
    c_not_i_g = []
    c_in_g_f  = get_group_members(group_name)
    contacts  = get_list_of_xmpp_addr()

    for c in c_eval_lst:
        if c in contacts and c != 'local':
            c_rm_list.append(c)
        else:
            c_unknown.append(c)

    try:
        with open('g.' + group_name + '.tfc', 'w') as f:
            for c in c_rm_list:
                if c not in c_in_g_f:
                    c_not_i_g.append(c)

            for c in c_in_g_f:
                if c in c_rm_list:
                    c_removed.append(c)
                else:
                    f.write(c + '\n')

    except IOError:
        exit_with_msg('ERROR! M(group_rm_member): g.%s.tfc could not be opened' % group_name)
        return None

    if c_removed:
        print "\nFollowing members were removed from group '%s':" % group_name
        for c in c_removed:
            print '    ' + c
        print ''

    if c_not_i_g:
        print "\nFollowing members were not in group '%s' to begin with:" % group_name
        for c in c_not_i_g:
            print '    ' + c
        print ''

    if c_unknown:
        print "\nFollowing unknown members are not in contacts:"
        for c in c_unknown:
            print '    ' + c
        print '\n'

    return None


def load_file_data(parameters):
    """
    Encode file to Base64 and load it as payload.

    :param parameters: Target file yet to be separated from command.
    :return:           None.

    By adding the TFCPROCESSED**** header, input_process can take
    care of preprocessing and move message to queue in it's own pace.
    This way constant time process does not get interrupted:
    long_msg_transmit() takes care of adding 1:1 ratio of TFCNOISECOMMANDs
    and ct_sleep() between packets so long transmission doesn't reveal
    communication taking place.
    """

    # Verify input parameter type.
    if not (isinstance(parameters, str)):
        exit_with_msg('CRITICAL ERROR! M(group_add_member): Wrong input type.')

    param_list = parameters.split(' ')
    file_name  = param_list[1]

    if yes('\nSend file %s to %s?' % (file_name, nick)):
        subprocess.Popen('base64 ' + file_name + ' > tfc_tmp_file', shell=True).wait()

        file_content = ''
        with open('tfc_tmp_file') as f:
            for line in f.readlines():
                line = line.strip('\n')
                file_content += line.strip()

        if not file_content:
            os.system('clear')
            print "\nError: target file '%s'  was empty. Transmission aborted.\n" % file_name
            return 'ABORT'

    else:
        print '\nFile sending aborted.\n'
        if not c_transmission:
            time.sleep(0.5)
        return 'ABORT'

    subprocess.Popen('shred -n ' + str(shred_iterations) + ' -z -u tfc_tmp_file', shell=True).wait()

    return 'TFCPROCESSEDFILE' + 'f' + file_content


def print_group_list():
    """
    Print list of groups and if print_group_contacts is True, their members.

    :return: None.
    """
    # Get list of availabel group files.
    g_file_list  = get_list_of_groups()

    if g_file_list:
        if print_g_contacts: print '\nAvailable groups and their members:'
        if not print_g_contacts: print '\nAvailable groups:'

        for g in g_file_list:
            print '    ' + g
            if print_g_contacts:
                print_group_members(g, True)
        print ''
    else:
        print '\nThere are currently no groups.\n'

    return None


def print_group_members(group_name, short=False):
    """
    Print list of existing groups (and their members).

    :param group_name: Target group.
    :param short:      When printing members of groups as part
                       of /groups command, leave out headers.
    :return:           None.
    """

    # Verify input parameter types.
    if not (isinstance(group_name, str) and isinstance(short, bool)):
        exit_with_msg('CRITICAL ERROR! M(print_group_members): Wrong input type.')

    if not group and group_name == '':
        print '\nNo group is selected.\n'
        return None

    if group and group_name == '':
        group_name = group

    try:
        g_members  = []

        with open('g.' + group_name + '.tfc') as f:
            for l in f.readlines():
                g_members.append(l.strip('\n'))

        if g_members:

            # Indent and leave out description if printed as part of all group files.
            if short:
                for m in g_members:
                    print '        ' + m
                print ''

            else:
                print '\nMembers in group %s' % group_name
                for m in g_members:
                    print '    ' + m
                print ''

        else:
            if short:
                print '        Group is empty.'
            else:
                print '\nGroup is empty.\n'

    except IOError:
        if short:
            print '    Group file %s does not exist.'   % group_name
        else:
            print "\nGroup file '%s' does not exist.\n" % group_name

    return None


def sort_group(group_name):
    """
    Alphabetize members of specified group.

    :param group_name: Name of groups to sort.
    :return:           None.
    """

    # Verify input parameter type.
    if not isinstance(group_name, str):
        exit_with_msg('CRITICAL ERROR! M(sort_group): Wrong input type.')

    try:
        with open('g.' + group_name + '.tfc') as f:
            members = f.readlines()
            members.sort()

        with open('g.' + group_name + '.tfc', 'w') as f:
            for member in members:
                f.write(member)

    except IOError:
        exit_with_msg('ERROR! M(sort_group): Group file g.%s.tfc could not be loaded.' % group_name)


######################################################################
#                                MISC                                #
######################################################################

def ch_debug(status):
    """
    Change global boolean debugging that determines
    if debuggin mode prints are enabled.

    :param status: Boolean value of setting.
    :return:       None.
    """

    # Verify input parameter type.
    if not isinstance(status, bool):
        exit_with_msg('CRITICAL ERROR! M(ch_debug): Wrong input type.')

    global debugging

    if status:
        print '\nDebugging has been enabled.\n'
        debugging = True
    else:
        print '\nDebugging has been disabled.\n'
        debugging = False

    return None


def get_terminal_width():
    """
    Get width of terminal Tx.py is running in.

    :return: The integer value of terminal width.
    """

    return int(subprocess.check_output(['stty', 'size']).split()[1])


def print_about():
    """
    Print information about TFC project.

    :return: None.
    """

    os.system('clear')
    print ' Tinfoil Chat CEV %s\n' % version
    print ' Homepage:\n'   + '  https://github.com/maqp/tfc-cev/\n'
    print ' Whitepaper:\n' + '  https://cs.helsinki.fi/u/oottela/tfc.pdf\n'
    print ' Manual:\n'     + '  https://cs.helsinki.fi/u/oottela/tfc-manual.pdf\n\n'

    return None


def print_help():
    """
    Print the list of commands.

    :return: None.
    """

    os.system('clear')

    width = get_terminal_width()

    if width < 66:
        le = '\n' + width * '-'
        print le
        print '/about\nDisplay information about TFC'                           + le
        print "/clear & '  '\nClear screens"                                    + le
        print '/help\nDisplay this list of commands'                            + le
        print '/logging <on/off>\nEnable/disable logging'                       + le
        print '/msg <ID/xmpp/group>\nChange recipient'                          + le
        print '/names\nDisplays available contacts'                             + le
        print '/paste\nEnable paste-mode'                                       + le
        print '/file <filename>\nSend file to recipient'                        + le
        print '/nick <nick>\nChange contact nickname'                           + le
        print '/quit & /exit\nExit TFC'                                         + le
        print '/store <b64 file> <output file>\nDecodes received file'          + le
        print '/group\nList members of selected group'                          + le
        print '/groups\nList currently available groups and their members'      + le
        print '/group <groupname>\nList members of <groupname>'                 + le
        print '/group create <groupname> <xmpp1> <xmpp2>\nCreate new group'     + le
        print '/group add <groupname> <xmpp1> <xmpp2>\nAdd xmpp to group'       + le
        print '/group rm <groupname> <xmpp1> <xmpp2>\nRemove xmpp from group'   + le
        print 'Shift + PgUp/PgDn\nScroll terminal up/dn'                        + le
        print '/store <tmp f.name> <output f.name>\nSave received tmp file'     + le
        print '/store <tmp f.name> r\nDiscart and overwrite received tmp file ' + le
        print '/store list\nRequest Rx.py to list pending tmp files '           + le
        print ''

    else:
        print 'List of commands:'
        print ' /about'               + 16 * ' ' + 'Show information about TFC'
        print " /clear & '  '"        + 9  * ' ' + 'Clear screens'
        print ' /file <file name>'    + 5  * ' ' + 'Send file to recipient'
        print ' /help'                + 17 * ' ' + 'Display this list of commands'
        print ' /logging <on/off>'    + 5  * ' ' + 'Enable/disable logging on Rx.py'
        print ' /msg <ID/xmpp/group>' + 2  * ' ' + 'Change recipient'
        print ' /names'               + 16 * ' ' + 'Displays available contacts'
        print ' /nick <nick>'         + 10 * ' ' + "Change contact's nickname"
        print ' /paste'               + 16 * ' ' + 'Enable paste-mode'
        print ' /quit & /exit'        + 9  * ' ' + 'Exits TFC'
        print ' Shift + PgUp/PgDn'    + 5  * ' ' + 'Scroll terminal up/down'

        print width * '-' + '\nGroup management:\n'

        print ' /groups'              + 15 * ' ' + 'List currently available groups'
        print ' /group'               + 16 * ' ' + 'List members of selected group'
        print ' /group <group name>'  + 3  * ' ' + 'List members of <groupname>\n'

        print (' /group create <group name> <xmpp 1> <xmpp 2> .. <xmpp n>       \n'
               '   Create new group named <group name>, add xmpp-addresses.     \n'
               '   Ask to overwrite current group if it exists.                 \n')

        print (' /group add <group name> <xmpp 1> <xmpp 2> .. <xmpp n>          \n'
               '   Add list of XMPP-addresses to group <group name>             \n'
               '   Ask to create group if it does not already exist.           \n')

        print (' /group rm <group name> <xmpp 1> <xmpp 2> .. <xmpp n>           \n'
               '   Remove xmpp-addresses from group <group name>.               \n'
               '   Ask to remove group if no xmpp addresses are provided.      \n')

        print width * '-' + '\nFile storing:\n'

        print (' /store <tmp file name> <output file name>  \n ' + 41 * '-' + '\n'
               '   Decode received file stored by Rx.py as <tmp file name>    \n'
               '   and store it as <output file name>. Shreds <tmp file name>.\n')

        print (' /store <tmp file name> r                   \n ' + 24 * '-' + '\n'
               '   Discart temp file <tmp file name>.                          \n')

        print (' /store list                                \n ' + 11 * '-' + '\n'
               '   Request Rx.py to list of pending tmp file names.            \n')

        return None


def tab_complete(text, state):
    """
    Auto-tab completer.

    :param text:  [not defined]
    :param state: [not defined]
    :return:      [not defined]
    """

    options  = [t for t in tab_get_list() if t.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None


def tab_get_list():
    """
    Create list for automatic tab completer.

    :return: List of autotabs.
    """

    auto_tabs = []

    auto_tabs += ['about', 'add ', 'clear', 'create ', 'exit', 'file ', 'group ', 'help',
                  'logging ', 'msg ', 'nick ', 'quit', 'rm ', 'select ', 'store ']

    auto_tabs += [(c + ' ') for c in get_list_of_xmpp_addr()]
    auto_tabs += [(g + ' ') for g in get_list_of_groups()]

    return auto_tabs


def yes(prompt):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked
    :return:       True if user types y(es), False if user types n(o).
    """

    # Verify input parameter type.
    if not isinstance(prompt, str):
        exit_with_msg('CRITICAL ERROR! M(yes): Wrong input type.')

    while True:
        try:
            selection = raw_input(prompt + ' (y/n): ')
        except KeyboardInterrupt:
            return False

        if selection.lower() in ('yes', 'y'):
            return True
        elif selection.lower() in ('no', 'n'):
            return False


##################################################################
#                         MULTIPROCESSING                        #
##################################################################

def sender_process():
    """
    Look for messages in mq, send noise-packets if not found.

    :return: [no return value]

    This function uses a cryptographically secure coin
    toss to create boolean values 1/2 : 1/2 ratio:
      Single byte B loaded from /dev/urandom has 256
    possible ord values - 128 even, 128 odd. By reducing
    the ord(B) value modulo 2, 1 or 0 is obtainedwith
    equal probability.

    This function first checks if queue has data in it.
    If it doesn't, it'll output noise messages and
    commands with 1:1 ratio. If queue has data, it first
    checks if it was a command: this determines the values
    used in the next coin toss.

    If loaded data was a command, independent coin tosses
    decide when to send the command: 1 for sending command,
    0 for outputting a noise message.

    If loaded data wasn't a command, independent coin tosses
    decide when to send the message: 1 for sending message,
    0 for outputting a noise command.

    If message is long, between every sent packet, the coin is
    tossed to determine whether a noise message is sent.

    This way, 1:1 ratio between command and message packets is
    always retained. Thus, guessing when communication takes
    place becomes much harder.
    """

    while True:

        sys.stdout.write('\r' + ' ' * (len(readline.get_line_buffer())) + '\r')

        if mq.empty():
            if ord(os.urandom(1)) % 2 == 1:
                command_transmit('TFCNOISECOMMAND')
                ct_sleep()
            else:
                main_loop('TFCNOISEMESSAGE')
                ct_sleep()

        else:
            mesg    = mq.get()
            was_cmd = False
            for c in ['/clear', ' ', '/store ', '/logging ', '/nick ']:
                    if mesg.startswith(c):
                        was_cmd = True

            if was_cmd:
                while was_cmd:
                    if ord(os.urandom(1)) % 2 == 1:
                        main_loop(mesg)
                        ct_sleep()
                        was_cmd = False
                    else:
                        main_loop('TFCNOISEMESSAGE')
                        ct_sleep()

            else:
                was_msg = True
                while was_msg:
                    if ord(os.urandom(1)) % 2 == 1:
                        main_loop(mesg)
                        ct_sleep()
                        was_msg = False
                    else:
                        command_transmit('TFCNOISECOMMAND')
                        ct_sleep()


def input_process(queue, fileno):
    """
    Get messages from raw_input, add them to mq.

    :param queue:  The queue where messages are added.
    :param fileno: Stdin file.
    :return:       None.
    """

    sys.stdin = os.fdopen(fileno)
    try:
        while True:
            if clear_input_screen:
                os.system('clear')
                print 'TFC-CEV %s || Tx.py || Constant transmission enabled\n\n'\
                      'Disabled: Contact switching, paste-mode, groups.\n' % version

            kb_string = raw_input('Message to %s: ' % xmpp)

            if kb_string.startswith('/file '):
                kb_string = load_file_data(kb_string)

            for disabled in ['/msg', '/paste', '/group']:
                if kb_string.startswith(disabled):
                    print '\nError. Disabled command.\n'
                    time.sleep(1.5)
                    kb_string = ''
                    continue

            queue.put_nowait(kb_string)

    except KeyboardInterrupt:
        exit_with_msg('')


##################################################################
#                            MAIN LOOP                           #
##################################################################

def get_normal_input():
    """
    Get input either from raw_input or readlines
    depending on whether paste_mode is enabled.

    :return: Return the input user entered.
    """

    user_input = ''

    global pastemode

    if group:
        prompt = 'Msg to group %s: ' % nick
    else:
        prompt = 'Msg to %s: '       % nick

    if pastemode:
        try:
            os.system('clear')
            print 'TFC-CEV %s || Tx.py\n' % version
            print 'Paste mode on || 2x ^D sends message || ^C exits\n\n%s\n' % prompt

            try:
                lines = sys.stdin.readlines()
            except IOError:
                print '\nError in STDIO. Please try again.\n'
                time.sleep(1)
                return ''

            user_input = '\n' + ''.join(lines)
            print '\nSending...'
            time.sleep(0.25)

        except KeyboardInterrupt:
            os.system('clear')
            print 'TFC-CEV %s || Tx.py\n' % version
            print 'Closing paste mode...\n\n%s\n' % prompt
            pastemode = False
            time.sleep(0.25)
            os.system('clear')
            return ''

    else:
        try:
            if clear_input_screen:
                os.system('clear')
                print 'TFC-CEV %s || Tx.py \n\n\n' % version
            user_input = raw_input(prompt)

            if user_input == '/paste':
                pastemode = True
                return ''

        except KeyboardInterrupt:
            if c_transmission:
                # Sleep just to make sure all keys are written.
                time.sleep(0.5)
            exit_with_msg('')

    return user_input


def main_loop(user_input):
    """
    Get user_input, xmpp and nick and send a command / message based on that.

    :param user_input: Message, noise packet or command.
    :return:           None.
    """

    # Verify input parameter type.
    if not isinstance(user_input, str):
        exit_with_msg('CRITICAL ERROR! M(main_loop): Wrong input type.')

    global debugging

    while True:

        if not c_transmission:

            global xmpp
            global nick
            global group

            if nick not in get_list_of_targets():

                os.system('clear')
                print 'TFC-CEV %s || Tx.py\n' % version
                print 'No contact is currently active.\n'
                group      = ''
                xmpp, nick = select_contact(print_contact_list())
                os.system('clear')
                print "\nNow sending messages to '%s' (%s)\n" % (nick, xmpp)

            user_input = get_normal_input()

        # Re-initialize tab autocomplete.
        readline.set_completer(tab_complete)
        readline.parse_and_bind('tab: complete')

        ##################################################################
        #                    GROUP MANAGEMENT COMMANDS                   #
        ##################################################################

        # Create new group.
        if user_input.startswith('/group create '):
            group_create(user_input)

        # List members of active group.
        elif user_input == '/group':
            print_group_members(group)

        # Add member to group.
        elif user_input.startswith('/group add '):
            group_add_member(user_input)

        # Remove member from group.
        elif user_input.startswith('/group rm '):
            group_rm_member(user_input)

        # List members of specified group.
        elif user_input.startswith('/group '):
            print_group_members(user_input.split(' ')[1])

        # List available groups (and their members).
        elif user_input == '/groups':
            print_group_list()

        ##################################################################
        #                      OTHER LOCAL COMMANDS                      #
        ##################################################################

        elif user_input.startswith('/msg '):
            change_recipient(user_input)

        elif user_input in ['/quit', '/exit']:
            quit_process(True)

        elif user_input == '/debugging on':
            ch_debug(True)

        elif user_input == '/debugging off':
            ch_debug(False)

        elif user_input == '/help':
            print_help()

        elif user_input == '/about':
            print_about()

        elif user_input == '/names':
            print_contact_list(True)

        elif user_input == '  ':
            if emergency_exit:
                quit_process()
            else:
                clear_screens(xmpp)

        elif user_input == '/clear':
            clear_screens(xmpp)

        elif user_input == '':
            if c_transmission:
                break
            else:
                continue

        ##################################################################
        #                       ENCRYPTED COMMANDS                       #
        ##################################################################

        elif user_input.startswith('/nick '):
            change_nick(xmpp, user_input)

        elif user_input.startswith('/logging '):
            change_logging(user_input)

        elif user_input.startswith('/store '):
            save_file(user_input)

        elif user_input.startswith('/') and not user_input.startswith('/file '):
            print '\nError: Invalid command.\n'
            if c_transmission:
                break
            else:
                continue

        elif user_input == 'TFCNOISECOMMAND':
            command_transmit(user_input)

        else:
            if group and c_transmission:
                print '\nWARNING! Constant transmission is enabled.\nGroup ' \
                      'messaging is disabled.\nPress enter to continue.'
                group = ''
                break

            #############################
            #     FILE TRANSMISSION     #
            #############################

            if user_input.startswith('/file '):
                user_input = load_file_data(user_input)

                if user_input == 'ABORT':
                    if c_transmission:
                        break
                    else:
                        continue

            if user_input.startswith('TFCPROCESSEDFILE'):
                send_msg_or_file(user_input[16:])

            ##############################
            #    MESSAGE TRANSMISSION    #
            ##############################

            else:
                user_input = 'm' + user_input
                send_msg_or_file(user_input)

        if c_transmission:
            break


##################################################################
#                              MAIN                              #
##################################################################

# Set default directory.
os.chdir(sys.path[0])

# Run self tests.
tfc_cev_self_test()
chk_pkg_size()

# Enable serial port if local testing is disabled.
if not local_testing:
    port = serial.Serial(serial_device, serial_baudrate, timeout=0.1)

# Search keyfiles.
search_keyfiles()

# Add new keyfiles.
add_keyfiles()

# Set default gobal variables.
group     = ''
pastemode = False

# Initialize tab-autocomplete.
readline.set_completer(tab_complete)
readline.parse_and_bind('tab: complete')

# Print header.
os.system('clear')
print 'TFC-CEV %s || Tx.py\n\n\n' % version

# Select contact.
caret_dst  = print_contact_list()
xmpp, nick = select_contact(caret_dst)

os.system('clear')

# Initialize multiprocessing when c_transmission is True.
if c_transmission:
    mq = Queue()
    fn = sys.stdin.fileno()

    qp = Process(target=input_process, args=(mq, fn))
    se = Process(target=sender_process)

    qp.start()
    se.start()
    qp.join()

# Else default msg input.
else:
    try:
        main_loop('')

    except KeyboardInterrupt:
        exit_with_msg('')

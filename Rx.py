#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-CEV (Cascading Encryption Version) || Rx.py
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
display_time          = True                   # Set True to enable time stamp printing.
display_time_fmt      = '%H:%M'                # Format of timestamps printed on screen.
log_time_stamp_fmt    = '%Y-%m-%d / %H:%M:%S'  # Format of timestamps in log files.

show_long_msg_warning = True                   # Set True to enable notification when
                                               # long message is being received from contact.

# Security settings
emergency_exit        = False                  # Enable emergency exit with double space as message.

shred_iterations      = 3                      # The number of iterations deleted files are
                                               # overwritten with secure delete / shred.


# Packet settings
file_saving_allowed   = False                  # Set True to enable storing received
                                               # files in their b64 encoded format.

keep_local_files      = False                  # Set True to enable storing files sent
                                               # to contact in their b64 encoded format.

# DoS protection
large_key_id_warning  = True                  # Set True to ask for manual approval when
                                               # hashing large offsets in received key.

large_key_id_limit    = 200                     # If upper is True, sets the limit after
                                               # which manual approval is required.

# Message logging
log_messages          = False                  # Set True to constantly log messages.
                                               # Can be enabled for session basis from TxM.

log_change_allowed    = True                   # Allow enabling and disabling logging from TxM.
log_tampering_event   = True                   # Log anomalities in received packets.


# Developer tools
injection_testing     = False                  # Injection testing mode.
debugging             = False                  # Set true to enable verbose messaging
                                               # about inner operations in Rx.py.

# Local testing mode: enabled when testing TFC on single computer.
local_testing = False

# Serial port settings
serial_baudrate       = 9600                   # Serial device speed.
serial_device         = '/dev/ttyAMA0'         # The serial device Rx.py reads data from.


######################################################################
#                                 IMPORTS                            #
######################################################################

import base64
import binascii
import csv
import datetime
import math
import os
import serial
import subprocess
import sys
import time
import zlib

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
    Encrypt plaintext with Keccak as PRF (CTR mode). (Used in Rx.py for self testing.)

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
    Decrypt ciphertext with Keccak in CTR mode.

    :param ctext:   Encrypted test string.
    :param hex_key: 256-bit self-test encryption key.
    :return:        Decrypted Keccak ciphertext.

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
    Encrypt plaintext with XSalsa20. (Used in Rx.py for self testing.)

    :param plaintext: Self test string to be encrypted.
    :param hex_key:   256-bit self-test encryption key.
    :return:          XSalsa20 ciphertext of self test string.

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
    key        = binascii.unhexlify(hex_key)

    # Generate unique nonce.
    iv         = os.urandom(24)

    # XOR plaintext with keystream to acquire ciphertext.
    ciphertext = XSalsa20_xor(plaintext, iv, key)

    return iv + ciphertext


def salsa20_decrypt(ctext, hex_key):
    """
    Decrypt ciphertext with Salsa20.

    :param ctext:   Encrypted test string.
    :param hex_key: Independent 256-bit encryption key.
    :return:        Decrypted Salsa20 ciphertext.

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
    Encrypt plaintext with Twofish in CTR mode. (Used in Rx.py for self testing.)

    :param plaintext: Self test string to be encrypted.
    :param hex_key:   256-bit self-test encryption key.
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
    Decrypt ciphertext with Twofish in CTR mode. (Used for self testing.)

    :param ctext:   CIphertext to be decrypted.
    :param hex_key: Independent 256-bit encryption key.
    :return:        Decrypted Twofish ciphertext.

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
    Encrypt plaintext with AES in GCM mode. (Used in Rx.py for self testing.)

    :param plaintext: Self test string to be encrypted.
    :param hex_key:   256-bit self-test encryption key.
    :return:          AES ciphertext of self test string.

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
    Decrypt and authenticate ciphertext with AES in GCM mode.

    :param ctext:   Encrypted test string.
    :param hex_key: Independent 256-bit encryption key.
    :return:        Decrypted AEC ciphertext.
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
def quad_decrypt(xmpp, ct4, key_id):
    """
    Decrypt plaintext with set of ciphers.

    :param xmpp:   The contact's XMPP-address (i.e. alice@jabber.org).
    :param ct4:    The outermost ciphertext.
    :param key_id: The key_id the packet claims to use*
    :return:       If authentication succeeds, the decrypted plaintext.

    *The key ID appended to the ciphertext tells Rx.py how many times it should
     have by then iterated the key through Keccak256. This function provides
     perfect forward secrecy without the need for constant key negotiation,
     which is impossible in TFC. This way loss of packets can be detected and
     keys are prevented from getting out of sync.

    Symmetric algorithms have not been proven secure. Based on the
    recommendations of the technical community including E. Snowden**,
    the symmetric encryption version uses a set of symmetric ciphers
    with different internal structures. This way the attacker would
    need to have attacks against several cryptographic primitives.

    **https://www.youtube.com/watch?v=7Ui3tLbzIgQ#t=12m40s

    Each cipher uses an independent 256-bit symmetric key yielding a
    total of 1024 bits of security, while at the same time providing
    perfect forward secrecy: By hashing the used encryption key with
    Keccak-256 (SHA3) immediately after use, previous key is deleted.
    """

    # Verify input parameter types.
    if not isinstance(xmpp, str) or not isinstance(ct4, str) or not isinstance(key_id, (int, long)):
        exit_with_msg('CRITICAL ERROR! M(decrypt): Wrong input type.')

    # Load expected keyset.
    key_set         = get_keyset(xmpp)

    # Calculate offset of contact's keyset.
    stored_key_id   = int(get_key_id(xmpp))
    keyid_in_packet = int(key_id)
    offset          = keyid_in_packet - stored_key_id

    if large_key_id_warning:
        if offset > large_key_id_limit:
            print '\nWARNING! KeyID suddenly rose with %s! This might indicate DoS\n' % str(offset)
            if not yes('  Proceed with hashing?'):
                return 'KEYIDFAIL'

    if offset > 0:

        # Notify user about missing messages implicated by the offset.
        if xmpp == 'rx.local':
            print '\nATTENTION! The last %s commands\nhave not been received from TxM.\n'        % str(offset)
        elif xmpp.startswith('me.'):
            print '\nATTENTION! The last %s messages sent to contact\n%s have not been received' % (str(offset), xmpp[3:])
        else:
            print '\nATTENTION! The last %s messages have not been received from %s'             % (str(offset), xmpp[3:])

        # Iterate keyset through Keccak hash function until there is no offset.
        i = 0
        while i < offset:
            n = 0
            while n < 4:
                key_set[n] = keccak256(key_set[n])
                n += 1
            i += 1

    # Decrypt ciphertext.
    ct3 = aes_gcm_decrypt(ct4, key_set[3])
    if ct3 == 'MACFAIL':
        return 'MACFAIL'

    ct2 = twofish_decrypt(ct3, key_set[2])
    ct1 = salsa20_decrypt(ct2, key_set[1])
    pt  = keccak_decrypt (ct1, key_set[0])

    # Store next keyset.
    rotate_keyset(xmpp, key_set)

    # Store key_id.
    write_key_id(xmpp, keyid_in_packet + 1)
    return pt


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
    print 'TFC %s || Rx.py || Running self tests...\n' % version

    # Run self tests.
    self_test_keccak_ctr()
    self_test_salsa20()
    self_test_twofish_ctr()
    self_Test_aes_gcm()

    print '\nAll tests successful.\n'
    time.sleep(0.5)
    os.system('clear')

    return None


######################################################################
#                            KEY MANAGEMENT                          #
######################################################################

def get_keyfile_list():
    """
    Get list of 'tx.xmpp.e' keyfiles in Tx.py directory

    :return: List of keyfiles.
    """

    kf_list  = []
    kf_list += [f for f in os.listdir('.') if f.endswith('.e') and (f.startswith('me.') or f.startswith('rx.'))]

    return kf_list


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

        with open(xmpp + '.e') as f:
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
                    exit_with_msg("CRITICAL ERROR! M(get_keyset): Illegal character '%s' in keyfile '%s.e'." % (c, xmpp))

            # Verify keys are of proper length.
            if len(key) != 64:
                exit_with_msg("CRITICAL ERROR! M(get_keyset): Illegal length key in keyfile '%s.e"     % xmpp)
            else:
                keyset.append(key)

    except IOError:
        exit_with_msg("CRITICAL ERROR! M(get_keyset): Failed to open keyfile '%s.e'" % xmpp)

    # Verify that four keys were loaded.
    if len(keyset) != 4:
        exit_with_msg("CRITICAL ERROR! M(get_keyset): Keyfile '%s.e' did not contain four keys."   % xmpp)

    # Verify that all keys are unique.
    if any(keyset.count(k) > 1 for k in keyset):
        exit_with_msg("CRITICAL ERROR! M(get_keyset): Two or more identical keys in keyfile '%s.e" % xmpp)

    # Print list of keys (for debugging purposes).
    if debugging and output:
        print "\nM(get_keyset): Loaded following set of keys for XMPP '%s':\n"   % xmpp
        for key in keyset:
            print key
        print '\n'

    return keyset


def search_keyfiles():
    """
    Check that at least one keyfile exists in Rx.py directory.

    :return: None.

    Remove instructions from end of keyfiles.
    Issue a warning if no keyfiles are found.
    """

    # Remove possible instruction from file names.
    for f in os.listdir('.'):
        if f.endswith('.e - Move this file to your RxM'):
            os.rename(f, f[:-29])

    for f in os.listdir('.'):
        if 'Give this file to' in f:
            new_name = f.split(' - Give this file to')[0]
            os.rename(f, new_name)

    # If loaded keyfile list is empty, exit.
    if not get_keyfile_list():
        exit_with_msg('Error: No keyfiles for contacts were found.\nMake sure keyfiles are in same directory as Rx.py.')
    return None


def rotate_keyset(xmpp, keyset):
    """
    Rotate next set of keys by replacing the key with it's Keccak256 digest.
    This operation removes previous keys providing perfect forward secrecy.

    :param xmpp:   The contact's XMPP-address (i.e. alice@jabber.org).
    :param keyset: Set of keys to write to target file.
    :return:       None.
    """

    # Verify input parameter types.
    if not isinstance(xmpp, str) or not isinstance(keyset, list):
        exit_with_msg('CRITICAL ERROR! M(rotate_keyset): Wrong input type.')

    try:
        new_keys = []
        with open(xmpp + '.e', 'w+') as f:
            for key in keyset:
                new_key = keccak256(key)
                new_keys.append(new_key)
                f.write(new_key + '\n')

    except IOError:
        exit_with_msg("CRITICAL ERROR! M(rotate_keyset): Keyfile '%s.e' could not be loaded" % xmpp)

    # Print list of written keys (for debugging purposes).
    if debugging:
        print "\nM(rotate_keyset): Wrote following keys to keyfile '%s.e':\n" % xmpp
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
#                           SECURITY RELATED                         #
######################################################################

def check_keyfile_parity():
    """
    Check that all me.xmpp.e files have
    matching rx.xmpp.e file and vice versa.

    :return: None.
    """

    # Create list of decryption key files.
    me_list        = []
    rx_list        = []
    me_list       += [f[3:][:-2] for f in os.listdir('.') if f.endswith('.e') and f.startswith('me.')]
    rx_list       += [f[3:][:-2] for f in os.listdir('.') if f.endswith('.e') and f.startswith('rx.') and f != 'rx.local.e']

    # Cross-check the two lists.
    not_receiving  = []
    not_sending    = []
    not_receiving += [c for c in me_list if c not in rx_list]
    not_sending   += [c for c in rx_list if c not in me_list]

    if not_receiving:
        print '\nWarning: Missing keyfiles! Messages received\nfrom following contacts can not be decrypted:\n'
        for contact in not_receiving:
            print '  ' + contact
            print ''

    if not_sending:
        print '\nWarning: Missing keyfiles! Messages sent to\nfollowing contacts can not be decrypted locally:\n'
        for contact in not_sending:
            print '  ' + contact
            print ''

    return None


def disp_opsec_warning():
    """
    Display OPSEC warning to users to remind
    them not to break the waterfall security.

    :return: None.
    """

    print ("\n                         WARNING!                             \n"
           "----------------------------------------------------------------\n"
           "DO NOT MOVE RECEIVED FILES FROM RxM TO LESS SECURE ENVIRONMENTS \n"
           "ESPECIALLY IF THEY ARE CONNECTED TO NETWORK EITHER DIRECTLY OR  \n"
           "INDIRECTLY! DOING SO WILL RENDER SECURITY PROVIDED BY SEPARATED \n"
           "TCB UNITS USELESS, AS MALWARE 'STUCK' IN RxM CAN EXFILTRATE KEYS\n"
           "AND/OR PLAINTEXT THROUGH THIS CHANNEL BACK TO THE ADVERSARY!    \n"
           "                                                                \n"
           "TO RETRANSFER A DOCUMENT, EITHER READ IT FROM RxM SCREEN USING  \n"
           "OCR SOFTWARE RUNNING ON TxM, OR SCAN DOCUMENT IN ANALOG FORMAT. \n"
           "IF YOUR LIFE DEPENDS ON IT, DESTROY THE USED TRANSMISSION MEDIA.\n"
           "----------------------------------------------------------------\n")

    return None


def packet_anomality(error_type='', packet_type=''):
    """
    Display and log message about packet anomality.

    :param error_type:  Error type determines the warning displayed.
    :param packet_type: Determines if packet is message or command.
    :return:            None.
    """

    # Verify input parameter types.
    if not isinstance(error_type, str) or not isinstance(packet_type, str):
        exit_with_msg('CRITICAL ERROR! M(packet_anomality): Wrong input type.')

    if error_type == 'MAC':
        print '\nWARNING! MAC of received %s failed!\n'    \
              'This might indicate a tampering attack!'    % packet_type
        error_msg = 'MAC of %s failed.'                    % packet_type

    elif error_type == 'replay':
        print '\nWARNING! %s has expired/invalid keyID!\n' \
              'This might indicate a tampering attack!'    % packet_type
        error_msg = 'Replayed ' + packet_type

    elif error_type == 'tamper':
        print '\nWARNING! Received a malformed %s!\nThis ' \
              'indicates transmission error or tampering!' % packet_type
        error_msg = 'Tampered / malformed '                + packet_type

    elif error_type == 'crc':
        print '\nWARNING! CRC of %s failed.\nThis might '  \
              'indicate problem in your RxM data diode.'   % packet_type
        error_msg = 'CRC error in '                        + packet_type

    elif error_type == 'hash':
        print '\nWARNING! Long %s hash failed This might ' \
              'indicate tampering or dropped packets.'     % packet_type
        error_msg = 'Invalid %s hash.'                     % packet_type

    elif error_type == 'key_id':
        error_msg = 'Sudden increase of KeyID in %s.'      % packet_type

    else:
        exit_with_msg('ERROR! M(packet_anomality): Invalid error type.')

    if log_tampering_event:

        timestamp = datetime.datetime.now().strftime(log_time_stamp_fmt)

        try:
            with open('syslog.tfc', 'a+') as f:
                f.write('%s AUTOMATIC LOG ENTRY: %s\n' % (timestamp, error_msg))

            print '\nThis event has been logged to syslog.tfc.\n'

        except IOError:
            exit_with_msg('CRITICAL ERROR! M(packet_anomality): Writing of packet anomality failed!')

    return None


def exit_with_msg(msg, emergency=False):
    """
    Exit Rx.py with message.

    :param msg: Message to display when exiting.
    :return:    None.
    """

    # Verify input parameter type.
    if not isinstance(msg, str):
        print '\nCRITICAL ERROR! M(exit_with_msg): Wrong input type.\nExiting TFC-CEV.\n'
        exit()

    os.system('clear')

    if emergency and msg == '':
        exit()

    print '\n%s\nExiting TFC-CEV.\n' % msg
    exit()


######################################################################
#                         CONTACT MANAGEMENT                         #
######################################################################

# rxc.tfc MANAGEMENT
def add_contact(nick, xmpp):
    """
    Add new contact to rxc.tfc.

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
        with open('rxc.tfc', 'a+') as f:
                f.write('%s,%s,1\n' % (nick, xmpp))

    except IOError:
        exit_with_msg('ERROR! M(add_contact): rxc.tfc could not be loaded.')

    if debugging:
        print '\nM(add_contact): Added contact %s (XMPP-addr = %s) to rxc.tfc.\n' % (nick, xmpp)

    return None


def add_keyfiles():
    """
    Prompt nick names for new contacts/keyfiles and store them to rxc.tfc.

    :return: None.
    """

    c_list = []

    try:
        with open('rxc.tfc', 'a+') as f:
            for row in csv.reader(f):
                c_list.append(row)

    except IOError:
        exit_with_msg('ERROR! rxc.tfc could not be loaded.')

    for kf in get_keyfile_list():
        existing = False
        xmpp     = kf[:-2]

        for c in c_list:
            if xmpp in c[1]:
                existing = True

        if not existing:

            if xmpp == 'rx.local':
                add_contact('local', 'rx.local')

            elif xmpp.startswith('rx.'):
                local_nick = xmpp.split('@')[0][3:]
                add_contact(local_nick, xmpp)
                continue

            elif xmpp.startswith('me.'):
                os.system('clear')
                print "TFC-CEV %s || Rx.py\n\nNew contact '%s' found." % (version, xmpp[3:])

                auto_nick = xmpp.split('@')[0][3:]                # Parse account name.
                auto_nick = auto_nick[0].upper() + auto_nick[1:]  # Capitalize.
                nick         = ''

                try:
                    nick = raw_input("\nGive nickname to contact or press enter to use '%s' as nick: " % auto_nick)
                except KeyboardInterrupt:
                    exit_with_msg('')

                if nick == '':
                    nick = auto_nick

                add_contact(nick, xmpp)
            else:
                continue

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
        c_list      = []
        key_id      = 0
        keyid_found = False

        with open('rxc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

        for i in range(len(c_list)):
            if c_list[i][1] == xmpp:
                key_id = int(c_list[i][2])
                keyid_found = True
        # Verify key_id is positive.

        if not (keyid_found or os.path.isfile(xmpp + '.e')):

            return -1

        if key_id > 0:
            return key_id
        else:
            exit_with_msg("ERROR! M(get_key_id): Failed to load valid key_id for contact '%s'." % xmpp)

    except ValueError:
        exit_with_msg(    "ERROR! M(get_key_id): Failed to load valid key_id for contact '%s'." % xmpp)

    except IOError:
        exit_with_msg(    'ERROR! M(get_key_id): rxc.tfc could not be loaded.')


def get_list_of_xmpp_addr():
    """
    Get list of available contact XMPP-addresses.

    :return: List of XMPP-addresses.
    """

    xmpp_a_list  = []
    xmpp_a_list += [f[:-2] for f in os.listdir('.') if f.endswith('.e') and (f.startswith('me.') or f.startswith('rx.'))]

    return xmpp_a_list


def get_nick(xmpp):
    """
    Load nick from rxc.tfc

    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :return:     The nickname for specified XMPP.
    """

    # Verify input parameter type.
    if not isinstance(xmpp, str):
        exit_with_msg('CRITICAL ERROR! M(get_nick): Wrong input type.')

    c_list = []

    try:
        with open('rxc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

    except IOError:
        exit_with_msg('ERROR! M(get_nick): rxc.tfc could not be loaded.')

    for i in range(len(c_list)):
        if c_list[i][1] == xmpp:
            nick = c_list[i][0]

            return nick

    exit_with_msg("ERROR! M(get_nick): Failed to load nick for XMPP '%s'." % xmpp)


def write_key_id(xmpp, keyid):
    """
    Write new key ID for contact to rxc.tfc.

    :param xmpp:  The contact's XMPP-address (i.e. alice@jabber.org).
    :param keyid: The counter of message, defines the offset in keyfile.
    :return:      None.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(keyid, (int, long))):
        exit_with_msg('CRITICAL ERROR! M(write_key_id): Wrong input type.')

    try:
        c_list = []

        with open('rxc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

        xmpp_found = False

        for i in range(len(c_list)):
            if c_list[i][1] == xmpp:
                xmpp_found   = True
                c_list[i][2] = keyid

        if not xmpp_found:
            exit_with_msg("ERROR! M(write_key_id): Could not find contact '%s' from rxc.tfc." % xmpp)

        with open('rxc.tfc', 'w') as f:
            csv.writer(f).writerows(c_list)

    except IOError:
        exit_with_msg('ERROR! M(write_key_id): rxc.tfc could not be loaded.')

        # Verify key_id has been properly written.
        new_stored_key = get_key_id(xmpp)
        if keyid != new_stored_key:
            exit_with_msg("CRITICAL ERROR! M(write_key_id): KeyID for contact '%s' was not properly stored to rxc.tfc." % xmpp)

        if debugging:
            print "\nM(write_key_id): Wrote key ID '%s' for contact '%s' to rxc.tfc\n" % (str(keyid), xmpp)

    return None


def write_nick(xmpp, nick):
    """
    Write new nick for contact to rxc.tfc.

    :param xmpp: The contact's XMPP-address (i.e. alice@jabber.org).
    :param nick: New nick for contact.
    :return:     None.
    """

    # Verify input parameter types.
    if not (isinstance(xmpp, str) and isinstance(nick, str)):
        exit_with_msg('CRITICAL ERROR! M(write_nick): Wrong input type.')

    try:
        c_list = []

        with open('rxc.tfc') as f:
            for row in csv.reader(f):
                c_list.append(row)

        nick_changed = False

        for i in range(len(c_list)):
            if c_list[i][1] == xmpp:
                c_list[i][0] = nick
                nick_changed = True

        if not nick_changed:
            exit_with_msg("ERROR! M(write_nick): Could not find XMPP '%s' from rxc.tfc." % xmpp)

        with open('rxc.tfc', 'w') as f:
            csv.writer(f).writerows(c_list)

        if debugging:
            print "\nM(write_nick): Wrote nick '%s' for XMPP '%s' to rxc.tfc\n" % (nick, xmpp)

    except IOError:
        exit_with_msg('ERROR! M(write_nick): rxc.tfc could not be loaded.')

    return None


######################################################################
#                           MSG PROCESSING                           #
######################################################################

def base64_decode(content):
    """
    Encode string to base64.

    :param content: String to be encoded.
    :return:        Encoded string.
    """

    # Verify input parameter type.
    if not isinstance(content, str):
        exit_with_msg('CRITICAL ERROR! M(base64_encode): Wrong input type.')

    try:
        decoded = base64.b64decode(content)
    except TypeError:
        return 'B64D_ERROR'

    return decoded


def clear_msg_file():
    """
    Clear the file NHoutput used to read
    data from NH.py in local testing mode.

    If Injection testing is enabled, also
    delete the content of intermediary file used.

    :return: None.
    """

    if local_testing:
        if injection_testing:
            open('INoutput', 'w+').close()
        open('NHoutput', 'w+').close()


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


def depadding(string):
    """
    Remove padding from plaintext.

    :param string: String to be depadded.
    :return:       String padding is removed from.
    """

    # Verify input parameter type.
    if not isinstance(string, str):
        exit_with_msg('CRITICAL ERROR! M(padding): Wrong input type.')

    return string[:-ord(string[-1:])]


def load_msg_from_f():
    """
    Load message from NHoutput-file when
    local testing mode is enabled.

    :return: Return message read from file.
    """

    msg = ''

    if injection_testing:
        with open('INoutput') as f:
            msg = f.readline()

        if debugging and msg not in ['', '\n']:
            print '\n\nM(load_msg_from_f): Loaded following packet\n%s\n' % msg

    else:
        with open('NHoutput') as f:
            msg = f.readline()

        if debugging and msg not in ['', '\n']:
            print '\n\nM(load_msg_from_f): Loaded following packet\n%s\n' % msg

    return msg


def process_command(cmd):
    """
    Process commands received from TxM.

    :param cmd: Command string.
    :return:    None.
    """
    # Verify input parameter type.
    if not isinstance(cmd, str):
        exit_with_msg('CRITICAL ERROR! M(process_command): Wrong input type.')

    global log_messages

    # Discart noise commands
    if cmd == 'TFCNOISECOMMAND':
        return None

    # Encrypted screen clearing
    if cmd == 'CLEARSCREEN':
        os.system('clear')
        return None

    ##########################
    #     Enable logging     #
    ##########################
    if cmd == 'LOGSON':

        if log_change_allowed:
            if log_messages:
                print '\nLogging is already enabled.\n'
            else:
                log_messages = True
                print '\nLogging has been enabled.\n'
            return None

        else:
            print "\nLogging settings can not be altered:\nBoolean value 'log_change_allowed' is set to False.\n"
            return None

    ###########################
    #     Disable logging     #
    ###########################
    if cmd == 'LOGSOFF':
        if log_change_allowed:
            if not log_messages:
                print '\nLogging is already disabled.\n'
            else:
                log_messages = False
                print '\nLogging has been disabled.\n'
            return None

        else:
            print "\nLogging settings can not be altered: Boolean\nvalue 'log_change_allowed' is set to False.\n"
            return None

    #################################
    #     Decode and store file     #
    #################################
    if cmd.startswith('STOREFILE '):
        not_used,  tmp_name, out_name = cmd.split(' ')
        store_file(tmp_name, out_name)
        return None

    #######################
    #     Change nick     #
    #######################
    if cmd.startswith('NICK '):
        not_used, xmpp, nick = cmd.split(' ')

        # Write and load nick.
        write_nick(xmpp, nick)
        stored_nick = get_nick(xmpp)

        print "\nChanged %s nick to %s\n" % (xmpp, stored_nick)

        return None


######################################################################
#                       COMMANDS AND FUNCTIONS                       #
######################################################################

def get_terminal_width():
    """
    Get width of terminal Tx.py is running in.

    :return: Return the integer value of terminal width.
    """

    return int(subprocess.check_output(['stty', 'size']).split()[1])


def list_tmp_files(showempty=False):
    """
    Print list of base64 encoded temporary files received from contacts

    :param showempty: When True, print also info about having no files.
    :return:          None.
    """

    # Verify input parameter type.
    if not isinstance(showempty, bool):
        print '\nCRITICAL ERROR! M(list_tmp_files): Wrong input type.\nExiting TFC-CEV.\n'
        exit()

    rem_f  = []
    rem_f += [f[2:][:-4] for f in os.listdir('.') if f.startswith('f.') and f.endswith('.tfc')]

    if rem_f:
        print 'Your RxM currently has following temporary files:'
        for f in rem_f:
            print '   ' + f
        print ''
    else:
        if showempty:
            print '\nNo pending tmp files were found.\n'
    return None



def store_file(pre, out):
    """
    Decode base64 encoded file, shred the temporary file.

    :param pre: Pre-assigned name of base64 encoded file.
    :param out: Name and extension of specified output file.
    :return:    None.
    """

    # Verify input parameter types.
    if not isinstance(pre, str) or not isinstance(out, str):
        exit_with_msg('CRITICAL ERROR! M(store_file): Wrong input type.')

    if pre == 'PRINT' and out == 'LIST':
        list_tmp_files(showempty=True)
        return None

    if not os.path.isfile('f.' + pre + '.tfc'):
        print "\nError: Could not find tmp file '%s'.\n" % pre
        list_tmp_files()
        return None

    if os.path.isfile(out):
        print '\nError: File already exists. Please use different file name.\n'
        return None

    shred_cmd = 'shred -n %s -z -u f.%s.tfc' % (str(shred_iterations), pre)

    if out != 'r':
        os.system('clear')

        dcc = 'base64 -d f.' + pre + '.tfc > ' + out

        subprocess.Popen(dcc, shell=True).wait()
        print "\nStored tmp file 'f.%s.tfc' as '%s'." % (pre, out)

        subprocess.Popen(shred_cmd, shell=True).wait()
        print "Temporary file 'f.%s.tfc' has been overwritten.\n" % pre

        disp_opsec_warning()

    else:
        subprocess.Popen(shred_cmd, shell=True).wait()
        print "Temporary file 'f.%s.tfc' was rejected and overwritten.\n" % pre

        list_tmp_files()

    return None


def write_log_entry(nick, xmpp, msg):
    """
    Write log file to store conversations.

    :param nick:     Nick name for contact.
    :param xmpp:     The contact's XMPP-address (i.e. alice@jabber.org).
    :param msg:      Message to store in log file.
    :return:         None.
    """

    # Verify input parameter types.
    if not isinstance(nick, str) or not isinstance(xmpp, str) or not isinstance(msg, str):
        exit_with_msg('CRITICAL ERROR! M(write_log_entry): Wrong input type.')

    msg       = msg.strip('\n')
    timestamp = datetime.datetime.now().strftime(log_time_stamp_fmt)

    try:
        with open('logs.' + xmpp[3:] + '.tfc', 'a+') as f:
            f.write('%s %s: %s\n' % (timestamp, nick, msg))

    except IOError:
        exit_with_msg('CRITICAL ERROR! M(write_log_entry): Writing message to log file failed!')

    if debugging:
        print "\nM(write_log_entry): Added log entry \n'%s' for contact %s\n" % (msg, xmpp[3:])

    return None


def yes(prompt):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked.
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


######################################################################
#                                MAIN                                #
######################################################################

# Set default directory.
os.chdir(sys.path[0])

# Run self tests
tfc_cev_self_test()

# Enable serial port if local testing is disabled.
if not local_testing:
    port = serial.Serial(serial_device, serial_baudrate, timeout=0.1)

# Run initial checks.
clear_msg_file()
search_keyfiles()

# Add new keyfiles.
add_keyfiles()

# Set global variables / dictionaries.
longMsgComplete = False
fileReceive     = False
longMsg         = {}


# Display configuration on header during start of program.
os.system('clear')

logsb  = 'on' if log_messages        else 'off'
fileb  = 'on' if file_saving_allowed else 'off'
print 'TFC-CEV %s || Rx.py || Logging %s || File reception %s\n' % (version, logsb, fileb)

# Check that me. and rx. key files have their pair.
check_keyfile_parity()

# Set initial dictionaries for file and message reception.
long_msg_on_way = {}
msg_received    = {}
message         = {}

for xmpp in get_list_of_xmpp_addr():
    long_msg_on_way[xmpp] = False
    msg_received[xmpp]    = False
    message[xmpp]         = ''

if file_saving_allowed:
    fileOnWay    = {}
    fileReceived = {}
    file_a       = {}

    for xmpp in get_list_of_xmpp_addr():
        fileOnWay[xmpp]    = False
        fileReceived[xmpp] = False
        file_a[xmpp]       = ''


######################################################################
#                                LOOP                                #
######################################################################

try:
    while True:
        time.sleep(0.01)
        received_packet = ''
        if local_testing:
            try:
                received_packet = load_msg_from_f()
                if not received_packet.endswith('\n'):
                    continue
            except IOError:
                continue

            clear_msg_file()

        else:
            received_packet = port.readline()

        if received_packet == '':
            continue

        try:
            # Process unencrypted commands.
            if received_packet.startswith('EXITTFC'):
                if emergency_exit:
                    exit_with_msg('', emergency=True)
                else:
                    exit_with_msg('')

            if received_packet.startswith('CLEARSCREEN'):
                os.system('clear')
                continue

            ####################################
            #         ENCRYPED COMMANDS        #
            ####################################
            if received_packet.startswith('<ctrl>'):
                cmd_mac_line, crc_pkg = received_packet[6:].split('~')
                crc_pkg               = crc_pkg.strip('\n')

                # Check that CRC32 Matches.
                if crc32(cmd_mac_line) != crc_pkg:
                    packet_anomality('crc', 'command')
                    continue

                payload, key_id = cmd_mac_line.split('|')
                key_id          = int(key_id)
                ciphertext      = base64_decode(payload)

                if ciphertext == 'B64D_ERROR':
                    packet_anomality('tamper', 'command')
                    continue

                try:
                    # Check that key_id is fresh.
                    if key_id < get_key_id('rx.local'):
                        packet_anomality('replay', 'command')
                        continue

                except UnboundLocalError:
                    print '\nFailed to load key ID for rx.local.e.\nCommand could not be executed.\n'
                    continue

                except ValueError:
                    print '\nFailed to load key ID for rx.local.e.\nCommand could not be executed.\n'
                    continue

                except KeyError:
                    packet_anomality('tamper', 'command')
                    continue

                except TypeError:
                    packet_anomality('tamper', 'command')
                    continue

                # Check that local keyfile for decryption exists.
                if not os.path.isfile('rx.local.e'):
                    print '\nError: rx.local.e was not found.\nCommand could not be decrypted.\n'
                    continue

                # Decrypt command if MAC verification succeeds.
                try:
                    decrypted_cmd = quad_decrypt('rx.local', ciphertext, key_id)
                    if decrypted_cmd == 'MACFAIL':
                        packet_anomality('MAC', 'command')
                        continue
                    if decrypted_cmd == 'KEYIDFAIL':
                        packet_anomality('key_id', 'message')
                        continue

                    # Remove padding.
                    command = depadding(decrypted_cmd)

                    # Process command.
                    process_command(command)

                except ValueError:
                        packet_anomality('MAC', 'command')
                        continue
                except TypeError:
                        packet_anomality('MAC', 'command')
                        continue

            ####################################
            #         NORMAL MESSAGE           #
            ####################################
            if received_packet.startswith('<mesg>'):
                xmpp, ct_mac_ln, crc_pkg = received_packet[6:].split('~')
                crc_pkg = crc_pkg.strip('\n')

                # Check that CRC32 Matches.
                if crc32(ct_mac_ln) != crc_pkg:
                    packet_anomality('crc', 'message')
                    continue

                payload, key_id = ct_mac_ln.split('|')
                key_id          = int(key_id)
                ciphertext      = base64_decode(payload)

                if ciphertext == 'B64D_ERROR':
                    packet_anomality('tamper', 'message')
                    continue

                try:
                    # Check that key_id is fresh.
                    if get_key_id(xmpp) == -1:
                        print '\nError! Missing keyfile:\nCould not decrypt packet from %s\n' % xmpp[3:]
                        continue

                    if int(key_id) < get_key_id(xmpp):
                        packet_anomality('replay', 'message')
                        continue

                except UnboundLocalError:
                    if xmpp.startswith('me.'):
                        print '\nFailed to load KeyID for %s.\nSent message could not be decrypted locally.\n' % xmpp[3:]
                    if xmpp.startswith('rx.'):
                        print '\nFailed to load KeyID for %s.\nReceived message could not be decrypted.\n'     % xmpp[3:]
                    continue

                except ValueError:
                    if xmpp.startswith('me.'):
                        print '\nFailed to load KeyID for %s.\nSent message could not be decrypted locally.\n' % xmpp[3:]
                    if xmpp.startswith('rx.'):
                        print '\nFailed to load KeyID for %s.\nReceived message could not be decrypted.\n'     % xmpp[3:]
                    continue

                except KeyError:
                    packet_anomality('tamper', 'message')
                    continue

                except TypeError:
                    packet_anomality('tamper', 'message')
                    continue

                # Check that keyfile for decryption exists.
                if not os.path.isfile(xmpp + '.e'):
                    print '\nError: keyfile for contact %s was not found.\nMessage could not be decrypted.\n' % xmpp
                    continue

                # Decrypt message if MAC verification succeeds.
                try:
                    decrypted_packet = quad_decrypt(xmpp, ciphertext, key_id)
                    if decrypted_packet == 'MACFAIL':
                        packet_anomality('MAC', 'message')
                        continue
                    if decrypted_packet == 'KEYIDFAIL':
                        packet_anomality('key_id', 'message')
                        continue

                    decrypted_packet = depadding(decrypted_packet)

                except ValueError:
                        packet_anomality('MAC', 'message')
                        continue

                except TypeError:
                        packet_anomality('MAC', 'message')
                        continue

                #########################################################
                #     Process cancelled messages and file transfers     #
                #########################################################

                """
                All received message/file-packets have header {s,l,a,e,c}{m,f}

                Second character:
                    m = message
                    f = file

                First character:
                    s = short packet: complete packet, process immediately.

                    l = first of    long msg / file.
                    a = appended to long msg / file.
                    e = last of     long msg / file, can be shown / stored.
                    c = cancelled   long msg / file, discarts packet content.
                """

                # Cancel file.
                if decrypted_packet.startswith('cf'):
                    if file_saving_allowed:
                        if fileOnWay[xmpp]:
                            if xmpp.startswith('me.'):
                                print "File transmission to contact '%s' cancelled.\n" % xmpp[3:]
                            if xmpp.startswith('rx.'):
                                print "Contact '%s' cancelled file transmission.\n"    % xmpp[3:]

                            fileOnWay[xmpp]    = False
                            fileReceived[xmpp] = False
                            file_a[xmpp]       = ''
                            continue

                # Cancel message.
                if decrypted_packet.startswith('cm'):
                    if long_msg_on_way[xmpp]:
                        if xmpp.startswith('me.'):
                            print "Long message to contact '%s' cancelled.\n"          % xmpp[3:]
                        if xmpp.startswith('rx.'):
                            print "Contact '%s' cancelled long message.\n"             % xmpp[3:]

                        long_msg_on_way[xmpp] = False
                        msg_received[xmpp]    = False
                        message[xmpp]         = ''
                        continue

                #####################################################
                #     Process short messages and file transfers     #
                #####################################################
                """
                Even if cf / cm packet dropped, Rx.py should inform user
                about interrupted reception of long message / file when
                short message / file is received.
                """

                # Short file.
                if decrypted_packet.startswith('sf'):
                    if file_saving_allowed:
                        if fileOnWay[xmpp]:
                            if xmpp.startswith('me.'):
                                print "File transmission to contact '%s' cancelled.\n" % xmpp[3:]
                            if xmpp.startswith('rx.'):
                                print "Contact '%s' cancelled file transmission.\n"    % xmpp[3:]

                        fileReceived[xmpp] = True
                        fileOnWay[xmpp]    = False
                        file_a[xmpp]       = decrypted_packet[2:]

                # Short message.
                if decrypted_packet.startswith('sm'):
                    if long_msg_on_way[xmpp]:
                        if xmpp.startswith('me.'):
                            print "Long message to contact '%s' cancelled.\n"          % xmpp[3:]
                        if xmpp.startswith('rx.'):
                            print "Contact '%s' cancelled long message.\n"             % xmpp[3:]

                    msg_received[xmpp]    = True
                    long_msg_on_way[xmpp] = False
                    message[xmpp]         = decrypted_packet[2:]

                    # If sender uses noise messages to hide when communication
                    # is actually taking place, discart the noise message to
                    # keep the chat feed clear.
                    if message[xmpp]  == 'TFCNOISEMESSAGE':
                        message[xmpp]  = ''
                        continue

                ####################################################
                #     Process long messages and file transfers     #
                ####################################################

                # Header packet of long file.
                if decrypted_packet.startswith('lf'):
                    if file_saving_allowed:
                        if fileOnWay[xmpp]:
                            if xmpp.startswith('me.'):
                                print "File transmission to contact '%s' cancelled.\n" % xmpp[3:]
                            if xmpp.startswith('rx.'):
                                print "Contact '%s' cancelled file transmission.\n"    % xmpp[3:]

                        # Print notification about receiving file.
                        if xmpp.startswith('me.'):
                            print "\nReceiving file sent to '%s'.\n"                   % xmpp[3:]
                        if xmpp.startswith('rx.'):
                            print "\nReceiving file from contact '%s'.\n"              % xmpp[3:]
                        fileReceived[xmpp] = False
                        fileOnWay[xmpp]    = True
                        file_a[xmpp]       = decrypted_packet[2:]
                        continue

                # Header packet of long message.
                if decrypted_packet.startswith('lm'):
                    if long_msg_on_way[xmpp]:
                        if xmpp.startswith('me.'):
                            print "Long message to contact '%s' cancelled.\n"          % xmpp[3:]
                        if xmpp.startswith('rx.'):
                            print "Contact '%s' cancelled long message.\n"             % xmpp[3:]

                    if show_long_msg_warning:
                        if xmpp.startswith('me.'):
                            print "\nReceiving long message sent to '%s'.\n"           % xmpp[3:]
                        if xmpp.startswith('rx.'):
                            print "\nReceiving long message from contact '%s'.\n"      % xmpp[3:]

                    msg_received[xmpp]    = False
                    long_msg_on_way[xmpp] = True
                    message[xmpp]         = decrypted_packet[2:]
                    continue

                # Append packet of long file.
                if decrypted_packet.startswith('af'):
                        if file_saving_allowed:
                            fileReceived[xmpp] = False
                            fileOnWay[xmpp]    = True
                            file_a[xmpp]       = file_a[xmpp] + decrypted_packet[2:]
                            continue

                # Append packet of long message.
                if decrypted_packet.startswith('am'):
                        msg_received[xmpp]    = False
                        long_msg_on_way[xmpp] = True
                        message[xmpp]         = message[xmpp] + decrypted_packet[2:]
                        continue

                # Final packet of long file.
                if decrypted_packet.startswith('ef'):
                    if file_saving_allowed:
                        file_a[xmpp] = file_a[xmpp] + decrypted_packet[2:]
                        fileContent  = file_a[xmpp][:-64]
                        hashOfFile   = file_a[xmpp][-64:]

                        if keccak256(fileContent) != hashOfFile:
                            os.system('clear')
                            packet_anomality('hash', 'file')
                            continue

                        file_a[xmpp]        = fileContent
                        fileReceived[xmpp]  = True
                        msg_received[xmpp]  = False
                        fileOnWay[xmpp]     = False

                # Final packet of long message.
                if decrypted_packet.startswith('em'):
                    message[xmpp] = message[xmpp] + decrypted_packet[2:]
                    msgContent    = message[xmpp][:-64]
                    hashOfMsg     = message[xmpp][-64:]

                    if keccak256(msgContent) != hashOfMsg:
                        os.system('clear')

                        packet_anomality('hash', 'message')
                        continue

                    message[xmpp]         = msgContent
                    msg_received[xmpp]    = True
                    long_msg_on_way[xmpp] = False
                    fileReceived[xmpp]    = False

                ######################################
                #     Process printable messages     #
                ######################################
                if msg_received[xmpp]:
                    if xmpp.startswith('me.'):
                        nick = 'Me > ' + get_nick(xmpp)
                    else:
                        nick = '     ' + get_nick('me' + xmpp[2:])

                    # Print timestamp and message to user.
                    if display_time:
                        timestamp = datetime.datetime.now().strftime(display_time_fmt)
                        print '%s  %s:  %s' % (timestamp, nick, message[xmpp])
                    else:
                        print     '%s:  %s' % (           nick, message[xmpp])

                    # Log messages if logging is enabled.
                    if log_messages:
                        if nick.startswith('Me > '):
                            spacing = len(get_nick('me' + xmpp[2:])) - 2
                            nick    = spacing * ' ' + 'Me'
                            write_log_entry(nick,     xmpp[3:], message[xmpp])
                        else:
                            write_log_entry(nick[5:], xmpp[3:], message[xmpp])

                    msg_received[xmpp]    = False
                    long_msg_on_way[xmpp] = False
                    message[xmpp]         = ''
                    continue

                ##################################
                #     Process received files     #
                ##################################
                if file_saving_allowed:

                    if fileReceived[xmpp]:

                        if xmpp.startswith('rx.') or (xmpp.startswith('me.') and keep_local_files):

                            # Generate random filename.
                            tmpfile     = 'f.%s.tfc'        % str(binascii.hexlify(os.urandom(2)))
                            while os.path.isfile(tmpfile):
                                tmpfile = 'f.%s.tfc'        % str(binascii.hexlify(os.urandom(2)))

                            # Store file.
                            try:
                                with open(tmpfile, 'w+') as f:
                                    f.write(file_a[xmpp])
                            except IOError:
                                exit_with_msg('Error in writing to file %s' % tmpfile)

                            if xmpp.startswith('me.'):
                                print "File sent to contact '%s' received locally.\n"     % xmpp[3:]

                            if xmpp.startswith('rx.'):
                                print "File transmission from contact '%s' complete.\n"   % xmpp[3:]

                            print ("Stored encoded file with temporary file name '%s'.\n\n"
                                   "Use command '/store %s <file name>' to save file or \n"
                                   "            '/store %s r' to reject file.           \n"
                                   % (tmpfile, tmpfile[2:][:-4], tmpfile[2:][:-4]))

                        if not xmpp.startswith('rx.') and keep_local_files:
                            print 'Locally received file was discarted.\n'

                        fileReceived[xmpp] = False
                        fileOnWay[xmpp]    = False
                        file_a[xmpp]       = ''
                        continue

        except IndexError:
            os.system('clear')
            packet_anomality('tamper', 'packet')
            continue

        except ValueError:
            os.system('clear')
            packet_anomality('tamper', 'packet')
            continue

except KeyboardInterrupt:
    exit_with_msg('')

#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-CEV (Cascading Encryption Version) || genKey.py
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
#                             CONFIGURING                            #
######################################################################

shred_iterations = 3     # Number of passes secure-delete overwrites tmp files.

instructions     = True  # Add instructions to files

keyboard_entropy = True  # Enable to ask user to input more entropy with keyboard.


######################################################################
#                                 IMPORTS                            #
######################################################################

import binascii
import math
import os
import subprocess
import sys
import time
from getpass import getpass


######################################################################
#                        KECCAK HASH FUNCTION                        #
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

    Licence:
    Algorithm Name: Keccak

    Authors: Guido Bertoni, Joan Daemen, Michael Peeters and Gilles
    Van Assche Implementation by Renaud Bauvin, STMicroelectronics

    This code, originally by Renaud Bauvin, is hereby put in the public
    domain. It is given as is, without any guarantee.

    For more information, feedback or questions, please refer to our
    website: http://keccak.noekeon.org/
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


def self_test_keccak():
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

    return None


def exit_with_msg(message):
    """
    Exit Rx.py with message.

    :param message: Message to display when exiting.
    :return:        None.
    """

    # Verify input parameter type.
    if not isinstance(message, str):
        print '\nCRITICAL ERROR! M(exit_with_msg): Wrong input type.\nExiting TFC-CEV.\n'
        exit()

    os.system('clear')
    print '\n%s\n\nExiting TFC-CEV.\n\n' % message
    exit()


def show_help():
    """
    Show help.

    :return: no return. Exit program.
    """

    print ('\nUsage: python genKey.py [OPTIONS]... CONTACT_XMPP USER_XMPP\n\n'
           '  -h, --hwrng'     + 6 * ' ' + 'Use HWRNG                      \n'
           '  -k, --urandom'   + 4 * ' ' + 'Use           /dev/urandom     \n'
           '  -K, --random'    + 5 * ' ' + 'Use           /dev/random      \n'
           '  -x, --urandomhw' + 2 * ' ' + 'Use HWRNG XOR /dev/urandom     \n'
           '  -X  --randomhw'  + 3 * ' ' + 'Use HWRNG XOR /dev/random    \n\n')
    exit()


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


######################################################################
#                          ENTROPY COLLECTION                        #
######################################################################

def get_hwrng_entropy(byte_len):
    """
    Load entropy from HWRNG with getEntropy and deskew program.

    :param byte_len:  Specify the amount of entropy to load.
    :return:          Return the specified amount of entropy.
    """

    entropy = ''
    while len(entropy) < byte_len:

        # Collect entropy from HWRNG.
        print 'Sampling entropy from HWRNG device...\n' \
              'Wait at least one minute before ending with Ctrl + C\n'
        try:
            subprocess.Popen('sudo ./getEntropy', shell=True).wait()
        except KeyboardInterrupt:
            pass


        # Clean messages after user issues KeyboardInterrupt.
        os.system('clear')
        print '\nTFC %s || Key generator || Mode: %s\n\n' % (version, mode)

        if def_output_file:
            print 'Specified output file: %s\n' % output_file

        print ('Sampling entropy from HWRNG device.                 \n'
               'Wait at least one minute before ending with Ctrl + C\n'
               'Ended by user.')


        # Apply von Neumann whitening.
        print        '\nApplying von Neumann whitening, round 1 / 2...'
        subprocess.Popen('cat HWRNGEntropy | ./deskew > firstDeskew', shell=True).wait()

        print 'Done.\n\nApplying von Neumann whitening, round 2 / 2...'
        subprocess.Popen('cat firstDeskew | ./deskew > secondDeskew', shell=True).wait()


        # Read whitened entropy.
        print 'Done.\n\nReading whitened entropy...'
        with open('deskewed') as f:
            bs = f.readline()


        # Convert '1011011101011...' to binary string.
        entropy = ''.join(chr(int(bs[i:i + 8], 2)) for i in xrange(0, len(bs), 8))


        # Overwrite temporary files.
        print 'Done.\n\nOverwriting HWRNG temporary files...'
        subprocess.Popen('shred -n %s -z -u HWRNGEntropy firstDeskew secondDeskew' % str(shred_iterations), shell=True).wait()

        # If not enough entropy, print warning and restart loop.
        if len(entropy) < byte_len:
            os.system('clear')
            print 'Error: Did not obtain enough entropy from HWRNG. Trying again.\n'
            time.sleep(2)

    # Return only 'byte_len' bytes of entropy.
    return entropy[:byte_len]


def get_dev_random(byte_len):

    entropy = ''
    while len(entropy) < byte_len:

        if not mixed_entropy:
            # Clean messages after user issues KeyboardInterrupt.
            os.system('clear')
            print '\nTFC %s || Key generator || Mode: %s\n\n' % (version, mode)
            if def_output_file:
                print 'Specified output file: %s\n' % output_file
        
        # Collect entropy from /dev/random.
        print 'Collecting entropy from /dev/random.\nThis may take up to 10 minutes...'
        subprocess.Popen('head -c %s /dev/random > dev_rand_ent' % str(byte_len), shell=True).wait()

        # Read entropy from file.
        print 'Done.\n\nReading collected entropy...'
        with open('dev_rand_ent', 'rb') as f:
            entropy = f.readline()

        # Shred temporary entropy files.
        print 'Done.\n\nShredding temporary entropy file...'
        subprocess.Popen('shred -n %s -z -u dev_rand_ent'        % str(byte_len), shell=True).wait()  

        # If not enough entropy, print warning and restart loop.
        if len(entropy) < byte_len:
            os.system('clear')
            print 'Error: Did not obtain enough entropy from /dev/random. Trying again.\n'

    # Return only 'byte_len' bytes of entropy.
    return entropy[:byte_len]


######################################################################
#                             ARGUMENTS                              #
######################################################################

# Initial Values, do not edit.
hwrng_entropy   = False
kernel_entropy  = False
mixed_entropy   = False
def_output_file = False
local_file      = False
user_xmpp       = ''

os.chdir(sys.path[0])

try:
    command         = str(sys.argv[1])
except IndexError:
    show_help()

try:
    output_file     = str(sys.argv[2])
except IndexError:
    def_output_file = True

try:
    user_xmpp       = str(sys.argv[3])
except IndexError:
    pass


sel_modes = 0

if '-h' in command or '--hwnrg' in command:
    mode           = 'HWRNG entropy'
    hwrng_entropy  = True
    use_dev_random = False
    sel_modes     += 1

if '-k' in command or '--urandom' in command:
    mode           = 'Kernel entropy (/dev/urandom)'
    kernel_entropy = True
    use_dev_random = False
    sel_modes     += 1

if '-K' in command or '--random' in command:
    mode           = 'Kernel entropy (/dev/random)'
    kernel_entropy = True
    use_dev_random = True
    sel_modes     += 1

if '-x' in command or '--urandomhw' in command:
    mode           = 'Mixed entropy (HWRNG XOR /dev/urandom)'
    mixed_entropy  = True
    use_dev_random = False
    sel_modes     += 1

if '-X' in command or '--randomhw' in command:
    mode           = 'Mixed entropy (HWRNG XOR /dev/random)'
    mixed_entropy  = True
    use_dev_random = True
    sel_modes     += 1

# Check that only one mode of operation is selected.
if sel_modes != 1:
    show_help()

######################################################################
#                               MAIN                                 #
######################################################################

self_test_keccak()

os.system('clear')
print '\nTFC %s || Key generator || Mode: %s\n\n' % (version, mode)


# If user gives no output file from command line, ask for key.
if def_output_file:
    try:
        output_file = raw_input('No output file specified.\n\nPlease enter recipient XMPP: ')
    except KeyboardInterrupt:
        os.system('clear')
        print '\nExiting genKey.py\n'
        exit()


# If user has given name of local keyfile, ask if genKey creates a pair of keys.
if output_file in ['l', 'local', 'local.e', 'tx.local', 'tx.local.e', 'rx.local', 'rx.local.e']:
    if yes('Create pair of local keys?'):
        local_file = True
        output_file = 'tx.local.e'

# If output_file has no extension, add '.e'.
if not output_file.endswith('.e'):    output_file += '.e'

# If output_file has no prefix, add 'tx.'
if not output_file.startswith('tx.'): output_file  = 'tx.' + output_file

# Remove {tx., rx., me.} from beginning and '.e' from end to get xmpp-address.
xmpp = output_file[3:][:-2]

# Initialize instructions.
inst_tx = ''
inst_me = ''
inst_co = ''

# If instructions are enabled, add them to files.
if instructions:

    # If Tx.py / Rx.pyalready exists, do not add instructions.
    inst_tx = '' if os.path.isfile('Tx.py') else ' - Move this file to your TxM'
    inst_me = '' if os.path.isfile('Rx.py') else ' - Move this file to your RxM'

    inst_co = ' - Give this file to ' + xmpp

# Check that previous keyfile is not overwritten.
if os.path.isfile(output_file + inst_tx):
    exit_with_msg('Error! Keyfile %s already exists.' % (output_file + inst_tx))

# To prevent errors with separators, prevent creation of keyfile that starts with dash.
if output_file.startswith('-'):
    exit_with_msg("\nError: Keyfile can not start with '-'. Exiting.\n")


######################################################################
#                      ENTROPY COLLECTION MODES                      #
######################################################################

# 128 bytes = 1024 bits or four 256-bit encryption keys.
if kernel_entropy:
    if use_dev_random:
        entropy = get_dev_random(128)
    else:
        print 'Collecting entropy from /dev/urandom...'
        entropy = os.urandom(128)

if hwrng_entropy:
    entropy     = get_hwrng_entropy(128)

if mixed_entropy:
    hw_entropy  = get_hwrng_entropy(128)

    if use_dev_random:
        print 'Done.\n'
        kernel_entropy = get_dev_random(128)
    else:
        print 'Done.\n\nCollecting entropy from /dev/urandom...'
        kernel_entropy = os.urandom(128)

    print 'Done.\n\nXOR:ing HWRNG and kernel entropy...'

    # XOR HWRNG entropy with Kernel entropy.
    if len(hw_entropy) == len(kernel_entropy):
        entropy = ''.join(chr(ord(hB) ^ ord(kB)) for hB, kB in zip(hw_entropy, kernel_entropy))
    else:
        exit_with_msg('CRITICAL ERROR: HWRNG - Kernel entropy length mismatch.')

# Split entropy to list of 32-byte (256-bit) strings.
keyList = [entropy[x:x + 32] for x in range(0, len(entropy), 32)]

# Verify that each key is of proper length.
for key in keyList:
    if len(key) != 32:
        exit_with_msg('CIRITICAL ERROR: Key list string was not 1024 bits')

# Verify that exactly four keys are obtained.
if len(keyList) != 4:
    exit_with_msg('ERROR: Illegal number of keys detecetd. Exiting.')

# Ask user to input random salt.
kbEntropy = ''
if keyboard_entropy:
    kbEntropy = getpass('Done.\n\nAdd to entropy pool with keyboard.\nPress enter when ready: ')

# Use Keccak256 to further whiten the entropy. Mix in entropy input by user.
with open(output_file + inst_tx, 'w+') as f:
    for key in keyList:
        hexKey = keccak256(kbEntropy + key)
        f.write(hexKey.upper() + '\n')


######################################################################
#                          KEYFILE DUPLICATION                       #
######################################################################

if local_file:

    if os.path.isfile('rx.local.e' + inst_tx):
        exit_with_msg('ERROR! Keyfile rx.local.e%s already exists. Exiting genKey.py' % inst_tx)

    # Store local encryption keys to files.
    print '\nCreating copies of key...'
    subprocess.Popen('cp "%s" "rx.local.e%s"' % ((output_file + inst_tx), inst_me), shell=True).wait()

    if not os.path.isfile('Tx.py'):
        subprocess.Popen('mkdir move_to_TxM',                       shell=True).wait()
        subprocess.Popen('mv "tx.local.e%s" move_to_TxM' % inst_tx, shell=True).wait()
        print "\nLocal key for Tx.py is inside 'move_to_TxM' folder."

    if not os.path.isfile('Rx.py'):
        subprocess.Popen('mkdir move_to_RxM',                       shell=True).wait()
        subprocess.Popen('mv "rx.local.e%s" move_to_RxM' % inst_me, shell=True).wait()
        print "\nLocal key for Rx.py is inside 'move_to_RxM' folder."


# Store other encryption keys to files.
else:
    if not user_xmpp:
        user_xmpp = raw_input('Done.\n\nIf you want to create triplet from your key,\n'
                              'enter your XMPP-account (else press Enter): ')

    if user_xmpp:

        # Check that previous keyfiles are not overwritten.
        if os.path.isfile('me.%s.e%s' % (xmpp, inst_me)):
            exit_with_msg('ERROR! Keyfile me.%s.e%s already exists. Exiting genKey.py' % (xmpp, inst_me))

        if os.path.isfile('rx.%s.e%s' % (xmpp, inst_co)):
            exit_with_msg('ERROR! Keyfile me.%s.e%s already exists. Exiting genKey.py' % (xmpp, inst_co))

        print '\nCreating copies of key...'
        subprocess.Popen("cp '%s' 'me.%s.e%s'" % ((output_file + inst_tx), xmpp, inst_me),      shell=True).wait()
        subprocess.Popen("cp '%s' 'rx.%s.e%s'" % ((output_file + inst_tx), user_xmpp, inst_co), shell=True).wait()

        # Depending on whether genKey is run on separated device,
        # TxM or local testing, keys are moved to useful folders.
        if not os.path.isfile('Tx.py'):
            subprocess.Popen('mkdir move_to_TxM',                              shell=True).wait()
            subprocess.Popen('mv "tx.%s.e%s move_to_TxM' % (xmpp, inst_tx),    shell=True).wait()
            print "\nKeys for your TxM are inside 'move_to_TxM' folder."

        if not os.path.isfile('Rx.py'):
            subprocess.Popen('mkdir move_to_RxM',                              shell=True).wait()
            subprocess.Popen('mv "me.%s.e%s move_to_RxM' % (xmpp, inst_me),    shell=True).wait()
            print "\nKeys for your RxM are inside 'move_to_RxM' folder"

        subprocess.Popen('mkdir contact_keys',                                 shell=True).wait()
        subprocess.Popen('mv "rx.%s.e%s" contact_keys' % (user_xmpp, inst_co), shell=True).wait()
        print '\nKeys for your contacts are inside \'contact_keys\' folder'

print '\nKeyfile(s) generated successfully.\nExiting.\n'
exit()

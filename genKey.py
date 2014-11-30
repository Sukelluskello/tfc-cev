#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import math
import os
import subprocess
import sys



######################################################################
#                               LICENCE                              #
######################################################################

# TFC-CEV (Cascading Encryption Version) || genKey.py
version = 'CEV 0.4.13 beta'

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
#                             CONFIGURING                            #
######################################################################

useDevRandom    = False # Higher quality entropy, interruptable, thus slower.

shredIterations = 3    # Number of passes secure-delete overwrites temporary keyfiles.




######################################################################
#                              ARGUMENTS                             #
######################################################################

# Initial Values, do not edit
HWRNGEntropy        = False
kernelEntropy       = False
mixedEntropy        = False
defOFile            = False



def showHelp():
    print '\nUsage: python genKey.py [OPTION]... OUTPUT_FILE'
    print '  -k' + 15 * ' ' + 'Use /dev/(u)random as entropy source'
    print '  -h' + 15 * ' ' + 'Use HW RNG as entropy source'
    print '  -b' + 15 * ' ' + 'Use HW RNG as source and XOR it with equal amount\n' \
                 + 19 * ' ' + 'of data from /dev/(u)random (Most secure option)'
    exit()



try:
    command = str(sys.argv[1])

except IndexError:
    showHelp()
    exit()

try:
    outputFile = str(sys.argv[2])
except IndexError:
    defOFile = True

if command == '-k':
    kernelEntropy   = True
    if useDevRandom:
        mode = 'Kernel entropy (/dev/random)'
    else:
        mode = 'Kernel entropy (/dev/urandom)'


if command == '-h':
    HWRNGEntropy    = True
    mode = 'HWRNG entropy'


if command == '-b':
    mixedEntropy    = True
    if useDevRandom:
        mode = 'Mixed entropy (HWRNG XOR /dev/random)'
    else:
        mode = 'Mixed entropy (HWRNG XOR /dev/urandom)'


if (command != '-k') and (command != '-h') and (command != '-b'):
    showHelp()
    exit()

os.chdir(sys.path[0])


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
    hexMsg       = binascii.hexlify(hashInput)
    return Keccak().Keccak(((8 * len(hashInput)), hexMsg), 1088, 512, 0, 256, 0)



######################################################################
#                          ENTROPY COLLECTION                        #
######################################################################

def get_hwrng_entropy(byteLen):

    entropy = ''
    while len(entropy) < byteLen:

        print 'Sampling randomness from HW RNG device...\nWait at least one minute before ending with Ctrl + C\n'
        try:
            subprocess.Popen('sudo ./getEntropy', shell=True).wait()
        except KeyboardInterrupt:
            pass

        print '\nVN whitening, round 1 / 2'
        subprocess.Popen('cat ' + 'HWRNGEntropy' + ' | ./deskew > ' + 'tmpDeskewed', shell=True).wait()

        print 'VN whitening, round 2 / 2'
        subprocess.Popen('cat ' + 'tmpDeskewed'  + ' | ./deskew > ' + 'deskewed',    shell=True).wait()

        print 'Done.'

        with open('deskewed', 'r') as file:
            binaryString = file.readline()

        # Convert '1011011101011...' to binary string
        entropy = ''.join(chr(int(binaryString[i:i+8], 2)) for i in xrange(0, len(binaryString), 8))

        if len(entropy) < byteLen:
            print 'Entropy collection failed. Trying again...'

        print '\n\nOverwriting HWRNG tmp files...'
        subprocess.Popen('sudo shred -n ' + str(shredIterations) + ' -z -u HWRNGEntropy tmpDeskewed deskewed', shell=True).wait()

    # Return only <byteLen> bytes of entropy
    return entropy[:byteLen]



def get_kernel_entropy(byteLen):
    print 'Collecting entropy from /dev/random. This may take up to 10 minutes...'
    subprocess.Popen('head -c ' + str(byteLen) + ' /dev/random > dev_rand_ent',   shell=True).wait()
    with open('dev_rand_ent', 'rb') as file:
        entropy = file.readline()

    while len(entropy) != byteLen:
        print 'Entropy collection from /dev/random failed. Trying again...'
        subprocess.Popen('head -c ' + str(byteLen) + ' /dev/random > dev_rand_ent',   shell=True).wait()
        with open('dev_rand_ent', 'rb') as file:
            entropy = file.readline()

    print 'Done.\n\n\nShredding temporary entropy file...'
    subprocess.Popen('shred -n ' + str(shredIterations) + ' -z -u dev_rand_ent', shell=True).wait()

    return entropy




######################################################################
#                      ENTROPY COLLECTION MODES                      #
######################################################################

os.system('clear')
print '\nTFC ' + version + ' || Key generator || Mode: ' + mode + '\n\n'


if defOFile:
    outputFile = raw_input('No output file specified. Please enter output file name: ')



# 128 bytes = 1024 bits = 4 * 256-bit encryption keys.

if kernelEntropy:
    if useDevRandom:
        entropy = get_kernel_entropy(128)
    else:
        print 'Collecting entropy from /dev/urandom...'
        entropy = os.urandom(128)



if HWRNGEntropy:
    entropy = get_hwrng_entropy(128)



if mixedEntropy:
    HWEntropy = get_hwrng_entropy(128)

    if useDevRandom:
        print 'Done.\n\n'
        kernelEnt = get_kernel_entropy(128)
    else:
        print 'Done.\n\n\nCollecting entropy from /dev/urandom...'
        KernelEntropy = os.urandom(128)

    print 'Done.\n\n\nXOR:ing HWRNG and kernel entropy...'


    # XOR HWRNG entropy with Kernel entropy.
    if len(HWEntropy) == len(KernelEntropy):
        entropy = ''.join(chr(ord(HWRNGByte) ^ ord(KernelByte)) for HWRNGByte, KernelByte in zip(HWEntropy, KernelEntropy))
    else:
        print 'ERROR: Length mismatch when XORing HWRNG entropy with kernel entropy. Exiting!'
        exit()


keyList   = [entropy[x:x+32] for x in range(0,len(entropy),32)]

kbEntropy = raw_input('\n\nType additional entropy with keyboard. Press enter when ready:\n\n')

with open(outputFile, 'w+') as file:
    for key in keyList:

        hexKey = keccak_256(kbEntropy + key)
        file.write(hexKey.upper() + '\n')



#########################################################
#               MAKE COPIES OF KEYFILE                  #
#########################################################

print 'Done.\n\n\nCreating copies of key...'
subprocess.Popen('cp ' + outputFile + ' me.' + outputFile, shell=True).wait()
subprocess.Popen('cp ' + outputFile + ' rx.' + outputFile + '_for_recipient', shell=True).wait()


print 'Done.\n\n\nPSK generation successful. Exiting.\n\n'
exit()



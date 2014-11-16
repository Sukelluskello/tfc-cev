#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import binascii
import string
import sys
import os



######################################################################
#                               LICENCE                              #
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
genKey.py
"""

version = '0.4.11 beta'



######################################################################
#                             CONFIGURING                            #
######################################################################

# Initial Values, do not edit
HWRNGEntropy        = False
kernelEntropy       = False
mixedEntropy        = False
defOFile            = False

# Settings
UseDevRandom        = True      # Higher quality entropy, interruptable, thus slower.
OverwriteIterations = 3         # Number of passes secure-delete overwrites temporary keyfiles.



######################################################################
#                          ENTROPY COLLECTION                        #
######################################################################

def getHWRNG(byteLen):

    entropy = ""
    while (len(entropy) < byteLen):

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

        with open('deskewed', 'rb') as file:
            binaryString = file.readline()

        # Convert '1011011101011...' to binary string
        entropy = ''.join(chr(int(binaryString[i:i+8], 2)) for i in xrange(0, len(binaryString), 8))

        if (len(entropy) < byteLen):
            print 'Entropy collection failed. Trying again...'

        print '\n\nOverwriting HWRNG tmp files...'
        subprocess.Popen('sudo shred -n ' + str(OverwriteIterations) + ' -z -u HWRNGEntropy tmpDeskewed deskewed', shell=True).wait()

    # Return only <byteLen> bytes of entropy
    return entropy[:byteLen]



def devRandom(byteLen):
    entropy = ""
    print 'Collecting entropy from /dev/random. This may take up to 10 minutes...'
    subprocess.Popen('head -c ' + str(byteLen) + ' /dev/random > dev_rand_ent',   shell=True).wait()
    with open('dev_rand_ent', 'rb') as file:
        entropy = file.readline()  
        
    while (len(entropy) != byteLen):
        print 'Entropy collection from /dev/random failed. Trying again...'
        subprocess.Popen('head -c ' + str(byteLen) + ' /dev/random > dev_rand_ent',   shell=True).wait()
        with open('dev_rand_ent', 'rb') as file:
            entropy = file.readline()

    print 'Done.\n\n\nShredding temporary entropy file...'
    subprocess.Popen('shred -n ' + str(OverwriteIterations) + ' -z -u dev_rand_ent', shell=True).wait()
    
    return entropy



######################################################################
#                              ARGUMENTS                             #
######################################################################

def showHelp():
    print '\nUsage: python genKey.py [OPTION]... OUTPUT_FILE'
    print '  -k' + 15* ' ' + 'Use /dev/(u)random as entropy source'
    print '  -h' + 15* ' ' + 'Use HW RNG as entropy source'
    print '  -b' + 15* ' ' + 'Use HW RNG as source and XOR it with equal amount\n' + 19 * ' ' + 'of data from /dev/(u)random (Most secure option)'
    exit()

try:
    command     = str(sys.argv[1])

except IndexError:
    showHelp()
    exit()

try:
    outputFile  = str(sys.argv[2])
except IndexError:
    defOFile = True

if (command == '-k'):
    kernelEntropy   = True
    if UseDevRandom:
        mode = 'Kernel entropy (/dev/random)'
    else:
        mode = 'Kernel entropy (/dev/urandom)'


if (command == '-h'):
    HWRNGEntropy    = True
    mode = 'HWRNG entropy'
    

if (command == '-b'):
    mixedEntropy    = True
    if UseDevRandom:
        mode = 'Mixed entropy (HWRNG XOR /dev/random)'
    else:
        mode = 'Mixed entropy (HWRNG XOR /dev/urandom)'


if (command != '-k') and (command != '-h') and (command != '-b'):
    showHelp()
    exit()

os.chdir(sys.path[0])

######################################################################
#                      ENTROPY COLLECTION MODES                      #
######################################################################

os.system('clear')
print '\nTFC ' + version + ' || Key generator\n\nMode: ' + mode + '\n\n'

if defOFile:
    outputFile = raw_input('No output file specified. Please enter output file name: ')

if kernelEntropy:

    if UseDevRandom:
        entropy = devRandom(128)
    else:
        print 'Collecting entropy from /dev/urandom...'
        entropy = os.urandom(128)



if HWRNGEntropy:
    entropy = getHWRNG(128)



if mixedEntropy:

    HWRNGent = getHWRNG(128)

    if UseDevRandom:
        print 'Done.\n\n'
        kernelEnt = devRandom(128)
    else:
        print 'Done.\n\n\nCollecting entropy from /dev/urandom...'
        kernelEnt = os.urandom(128)

    print 'Done.\n\n\nXOR:ing HWRNG and kernel entropy...'

    if (len(HWRNGent) == len(kernelEnt)):
        entropy = ''.join(chr(ord(HWRNGByte) ^ ord(KernelByte)) for HWRNGByte, KernelByte in zip(HWRNGent, kernelEnt))
    else:
        print 'ERROR: Length mismatch when XORing HWRNG entropy with kernel entropy. Exiting!'
        exit()


keyList = [entropy[x:x+32] for x in range(0,len(entropy),32)]


with open(outputFile, 'w+') as file:
    for key in keyList:
        hexKey  = binascii.hexlify(key)
        file.write(hexKey + '\n')


print 'Done.\n\n\nCreating copies of key...'
subprocess.Popen('cp ' + outputFile + ' me.' + outputFile, shell=True).wait()
subprocess.Popen('cp ' + outputFile + ' rx.' + outputFile + '_for_recipient', shell=True).wait()


print 'Done.\n\n\nPSK generation successful. Exiting.\n\n'
exit()




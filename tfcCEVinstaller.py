#!/usr/bin/env python
#-*- coding: utf-8 -*-

import binascii
import os
import sys
import subprocess
import time


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
tfcCEVinstaller.py
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
#                      PyCrypto Library install                      #
######################################################################

def pyCrypto_Install():

    appRdir = os.getcwd()
    print '\nInstalling Python-dev\n'
    subprocess.Popen('sudo apt-get --yes install python-dev',                       shell=True).wait()

    print '\nDownloading PyCrypto Library\n'
    subprocess.Popen('wget https://github.com/dlitz/pycrypto/archive/master.zip',   shell=True).wait()

    print '\nUnzipping PyCrypto Library\n'
    subprocess.Popen('unzip master.zip',                                            shell=True).wait()
    os.chdir('pycrypto-master/')

    print '\nInstalling PyCrypto Library\n'
    subprocess.Popen('sudo python setup.py install',                                shell=True).wait()
    os.chdir(appRdir)

    print '\nRemoving master.zip (PyCrypto download file, unzipped files remain)\n'
    subprocess.Popen('rm master.zip',                                               shell=True).wait()



######################################################################
#                             APT COMMANDS                           #
######################################################################

def update_system():
    print '\nUpdating system\n'
    subprocess.Popen('sudo apt-get --yes update',                shell=True).wait()



def install_Python_Serial():
    print '\nInstalling Python-serial\n'
    subprocess.Popen('sudo apt-get --yes install python-serial', shell=True).wait()



def install_Python_Qt4():
    print '\nInstalling Python QT4\n'
    subprocess.Popen('sudo apt-get --yes install python-qt4',    shell=True).wait()



def install_Python_pip():
    print '\nInstalling Python pi\n'
    subprocess.Popen('sudo apt-get --yes install python-pip',    shell=True).wait()
    
    

def install_SecureDelete():
    print '\nInstalling Secure Delete\n'
    subprocess.Popen('sudo apt-get --yes install secure-delete', shell=True).wait()



def install_DieHarder():
    print '\nInstalling Dieharder suite\n'
    subprocess.Popen('sudo apt-get --yes install dieharder',     shell=True).wait()



def install_Ent():
    print '\nInstalling Ent entropy analysis suite\n'
    subprocess.Popen('sudo apt-get --yes install ent',           shell=True).wait()



def install_Pidgin():
    print '\nInstalling Pidgin\n'
    subprocess.Popen('sudo apt-get --yes install pidgin',        shell=True).wait()



def install_Pidgin_OTR():
    print '\nInstalling Pidgin OTR\n'
    subprocess.Popen('sudo apt-get --yes install pidgin-otr',    shell=True).wait()




######################################################################
#                            ZYPPER COMMANDS                         #
######################################################################

def zypper_Pidgin():
    print '\nInstalling Pidgin\n'
    subprocess.Popen('sudo zypper install pidgin',        shell=True).wait()



def zypper_Pidgin_OTR():
    print '\nInstalling Pidgin OTR\n'
    subprocess.Popen('sudo zypper install pidgin-otr',    shell=True).wait()



def zypper_Python_Serial():
    print '\nInstalling Python-serial\n'
    subprocess.Popen('sudo zypper install python-serial', shell=True).wait()



def zypper_Python_Qt4():
    print '\nInstalling Python QT4\n'
    subprocess.Popen('sudo zypper install python-qt4',    shell=True).wait()


######################################################################
#                             APT COMMANDS                           #
######################################################################

def pip_salsa20():
    print '\nInstalling Salsa20 crypto-library\n'
    subprocess.Popen('sudo pip install salsa20',    shell=True).wait()

def pip_twofish():
    print '\nInstalling Twofish crypto-library\n'
    subprocess.Popen('sudo pip install twofish',    shell=True).wait()


######################################################################
#                              YUM COMMANDS                          #
######################################################################

def yum_Pidgin():
    print '\nInstalling Pidgin\n'
    subprocess.Popen('sudo yum install pidgin',     shell=True).wait()



def yum_Pidgin_OTR():
    print '\nInstalling Pidgin OTR\n'
    subprocess.Popen('sudo yum install pidgin-otr', shell=True).wait()



def yum_install_Wget():
    print '\nInstalling Wget\n'
    subprocess.Popen('sudo yum install wget',       shell=True).wait()



def yum_Python_Serial():
    print '\nInstalling Python-serial\n'
    subprocess.Popen('sudo yum install pyserial',   shell=True).wait()



def yum_Python_Qt4():
    print '\nInstalling Python QT4\n'
    subprocess.Popen('sudo yum install pyqt4',      shell=True).wait()



######################################################################
#                      FILE CONTENT CONFIGURING                      #
######################################################################

def rasp_cmdline():
    # Edit /boot/cmdline.txt to enable serial port for user (phase 1/2)
    print '\nEditing file \'cmdline.txt\'\n'

    with open('/boot/cmdline.txt', 'r') as bootfile:
        line        = bootfile.readline()
        line        = line.replace(' console=ttyAMA0,115200 kgdboc=ttyAMA0,115200', '')
    with open('/boot/cmdline.txt', 'w+') as bootfile:
        bootfile.write(line)



def rasp_inittab():
    # Edit /etc/inittab to enable serial port for user (phase 2/2)
    print '\nEditing file \'inittab\'\n'

    with open('/etc/inittab', 'r') as inittfile: 
        contents    = inittfile.read()
        rep_contents    = contents.replace('T0:23:respawn:/sbin/getty -L ttyAMA0 115200 vt100', '#T0:23:respawn:/sbin/getty -L ttyAMA0 115200 vt100')

    with open('/etc/inittab',"w+") as inittfile:
        inittfile.write(rep_contents)



def x86_SerialConfig(scriptName):
    # Configure serial port of Tx.py/Rx.py for USB adapters
    print '\nConfiguring serial interfaces of \'' + scriptName + '\'\n'

    with open(scriptName, 'r') as scriptF:
        contents    = scriptF.read()
        fixedContent    = contents.replace('\'/dev/ttyAMA0\'', '\'/dev/ttyUSB0\'')

    with open(scriptName, 'w+') as scriptF:
        scriptF.write(fixedContent)



def changeToLocal(fileName):
    # Configure Tx/Rx/NH.py localTesting boolean to True
    print '\nChanging boolean \'localTesting\' of file \'' + fileName + '\' to \'True\''

    with open(fileName, 'r') as tfcApp:
        contents    = tfcApp.read()
        rep_contents    = contents.replace('localTesting    = False', 'localTesting    = True\n')

    with open(fileName, 'w+') as tfcApp:
        tfcApp.write(rep_contents)



######################################################################
#                          SCRIPT DOWNLOADING                        #
######################################################################

def get_TxM_scripts():
    print '\nDownloading TFC-suite (TxM)\n'
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/Tx.py',        shell=True).wait()
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/genKey.py',    shell=True).wait()
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/getEntropy.c', shell=True).wait()
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/deskew.c',     shell=True).wait()



def get_RxM_scripts():
    print '\nDownloading TFC-suite (RxM)\n'
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/Rx.py', shell=True).wait()



def get_NH_script():
    print '\nDownloading TFC-suite (NH)\n'
    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/NH.py', shell=True).wait()



######################################################################
#                             MISC COMMANDS                          #
######################################################################

def reboot():
    subprocess.Popen('sudo reboot',                                  shell=True).wait()



def SetSerialPermissions(username):
    print '\nChanging serial port permissions for user \'' + username + '\'\n'
    subprocess.Popen('sudo gpasswd --add ' + username + ' dialout',  shell=True).wait()



def compile_C_programs():
    print '\nCompiling C-programs\n'
    subprocess.Popen('sudo gcc -Wall -O getEntropy.c -o getEntropy', shell=True).wait()
    subprocess.Popen('sudo gcc -Wall -O deskew.c -o deskew',         shell=True).wait()



def enable_C_execute():
    print '\nEnabling permissions to execute compiled C-programs\n'
    subprocess.Popen('sudo chmod a+x getEntropy',                    shell=True).wait()
    subprocess.Popen('sudo chmod a+x deskew',                        shell=True).wait()



def printLocalTesterWarning():
    print """
WARNING YOU HAVE SELECTED TO INSTALL LOCAL TESTING VERSION OF TFC!
THIS VERSION IS INTENDED FOR TRYING OUT THE FEATURES AND STABILITY OF SYSTEM.
AS ENCRYPTION KEYS ARE HANDLED ON SAME COMPUTER THAT IS CONNECTED ONLINE,
ANYONE WHO BREAKS IN TO YOUR COMPUTER BY EXPLOITING A KNOWN OR UNKNOWN
VULNERABILITY, CAN DECRYPT AND/OR FORGE ALL MESSAGES YOU SEND AND RECEIVE,
EFFORTLESSLY!
"""

def create_keyfile(name):
    i = 0
    with open(name, 'w+') as eFile:
        while (i < 4):
            binKey = os.urandom(32)
            key    = binascii.hexlify(binKey)
            eFile.write(key+'\n')
            i += 1



######################################################################
#                              MAIN LOOP                             #
######################################################################

while True:
    try:
        os.system('clear')
        print 'TFC-CEV Installer (Version ' + version + ')\n'
        print 'Select configuration that matches your OS:'


        print '   TxM'
        print '      1.  Raspbian\n'

        print '      2.  Ubuntu'
        print '          Kubuntu'
        print '          Linux Mint (Ubuntu/Debian)\n'

        print '   RxM'
        print '      3.  Raspbian\n'

        print '      4.  Ubuntu'
        print '          Kubuntu'
        print '          Linux Mint (Ubuntu/Debian)\n'

        print '    NH'
        print '      5.  Ubuntu'
        print '          Kubuntu'
        print '          Linux Mint (Ubuntu/Debian)\n'

        print '      6.  Tails\n'

        print '      7.  OpenSUSE\n'
        
        print '      8.  Fedora\n'

        print '    Local Testing (insecure)'
        print '      9.  Ubuntu'
        print '          Kubuntu'
        print '          Linux Mint (Ubuntu/Debian).'

        selection = int(raw_input('\n1..9: '))



    ######################################################################
    #                                  TxM                               #
    ######################################################################

    #TxM Raspbian
        if (selection == 1):
            os.system('clear')
            if (raw_input('This will install TxM configuration for Raspbian. \nAre you sure? Type uppercase YES: ') == 'YES'):
                rasp_cmdline()
                rasp_inittab()
                update_system()
                pyCrypto_Install()
                install_Python_pip()
                pip_salsa20()
                pip_twofish()
                install_Python_Serial()
                install_SecureDelete()
                install_Ent()
                install_DieHarder()
                get_TxM_scripts()
                compile_C_programs()
                enable_C_execute()

                os.system('clear')
                print '\nTxM install script completed\nRebooting system in 20 seconds. If you don\'t want to restart now, press CTRL+C'
                print '\nNote that you can remove the pycrypto-master folder if you\'re not going to audit the library. '
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print "\n\nReboot aborted, exiting. (You may need to restart your TxM for Tx.py to work correctly)\n"
                    exit()
            else:
                continue



    #TxM Ubuntu
        if (selection == 2):
            os.system('clear')
            if (raw_input('This will install TxM configuration for Ubuntu / Mint (Ubuntu / Debian). \nAre you sure? Type uppercase YES: ') == 'YES'):
                update_system()
                install_SecureDelete()
                install_Ent()
                install_DieHarder()
                pyCrypto_Install()
                install_Python_pip()
                pip_salsa20()
                pip_twofish()
                install_Python_Serial()
                get_TxM_scripts()
                compile_C_programs()
                enable_C_execute()
                x86_SerialConfig('Tx.py')
                SetSerialPermissions(raw_input("Type name of the user that will be running TFC (this will add the user to dialout group): "))

                os.system('clear')
                print '\nTxM install script completed\nRebooting system in 20 seconds. If you don\'t want to restart now, press CTRL+C'
                print '\nNote that you can remove the pycrypto-master folder if you\'re not going to audit the library. '
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print "\n\nReboot aborted, exiting. (You may need to restart your TxM for Tx.py to work correctly)\n"
                    exit()
            else:
                continue



    ######################################################################
    #                                  RxM                               #
    ######################################################################

    #RxM Raspbian
        if (selection == 3):
            os.system('clear')
            if (raw_input('This will install RxM configuration for Raspbian. \nAre you sure? Type uppercase YES: ') == 'YES'):
                rasp_cmdline()
                rasp_inittab()
                update_system()
                pyCrypto_Install()
                install_Python_pip()
                pip_salsa20()
                pip_twofish()
                install_Python_Serial()
                install_SecureDelete()
                get_RxM_scripts()

                os.system('clear')
                print '\nRxM install script completed\nRebooting system in 20 seconds. If you don\'t want to restart now, press CTRL+C'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print "\n\nReboot aborted, exiting. (You may need to restart your RxM for Rx.py to work correctly)\n"
                    exit()
            else:
                continue



    #RxM Ubuntu
        if (selection == 4):
            os.system('clear')
            if (raw_input('This will install RxM configuration for Ubuntu / Mint (Ubuntu / Debian). \nAre you sure? Type uppercase YES: ') == 'YES'):
                update_system()
                install_SecureDelete()
                pyCrypto_Install()
                install_Python_pip()
                pip_salsa20()
                pip_twofish()
                install_Python_Serial()
                SetSerialPermissions(raw_input("Type name of the user that will be running TFC (this will add the user to dialout group): "))
                
                get_RxM_scripts()
                x86_SerialConfig('Rx.py')

                os.system('clear')
                print '\nRxM install script completed\nRebooting system in 20 seconds. If you don\'t want to restart now, press CTRL+C'
                print '\nNote that you can remove the pycrypto-master folder if you\'re not going to audit the library. '
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:

                    print "\n\nReboot aborted, exiting. (You may need to restart your RxM for Rx.py to work correctly)\n"
                    exit()
            else:
                continue



    ######################################################################
    #                                   NH                               #
    ######################################################################

    #NH Ubuntu
        if (selection == 5):
            os.system('clear')
            if (raw_input('This will install NH configuration for Ubuntu / Mint (Ubuntu / Debian). \nAre you sure? Type uppercase YES: ') == 'YES'):
                update_system()
                if (raw_input('\nType YES to install Pidgin with OTR: ') == 'YES'):
                    install_Pidgin()
                    install_Pidgin_OTR()
                install_Python_Qt4()
                install_Python_Serial()
                SetSerialPermissions(raw_input("Type name of the user that will be running TFC (this will add the user to dialout group): "))
                get_NH_script()
                
                os.system('clear')
                print '\nNH install script completed\nRebooting system in 20 seconds. If you don\'t want to restart now, press CTRL+C'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print "\n\nReboot aborted, exiting. (You may need to restart your NH for NH.py to work correctly)\n"
                    exit()
            else:
                continue



    #NH Tails (The Amnesic Incognito Live System)
        if (selection == 6):
            os.system('clear')
            if (raw_input('This will install NH configuration for Tails. \nAre you sure? Type uppercase YES: ') == 'YES'):
                SetSerialPermissions('amnesia')
                get_NH_script()
                os.system('clear')
                print '\nNH install script completed. To launch NH, type below\n                   python NH.py'
                exit()
            else:
                continue



    #NH OpenSUSE
        if (selection == 7):
            os.system('clear')
            if (raw_input('This will install NH configuration for OpenSUSE. \nAre you sure? Type uppercase YES: ') == 'YES'):
                if (raw_input('\nType YES to install Pidgin with OTR: ') == 'YES'):
                    zypper_Pidgin()
                    zypper_Pidgin_OTR()
                zypper_Python_Qt4()
                zypper_Python_Serial()
                SetSerialPermissions(raw_input("Type name of the user that will be running TFC (this will add the user to dialout group): "))
                get_NH_script()
                
                os.system('clear')
                print '\nNH install script completed\nRebooting system in 20 seconds. If you don\'t want to restart now, press CTRL+C'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print "\n\nReboot aborted, exiting. (You may need to restart your NH for NH.py to work correctly)\n"
                    exit()
            else:
                continue



    #NH Fedora
        if (selection == 8):
            os.system('clear')
            if (raw_input('This will install NH configuration for Fedora. \nAre you sure? Type uppercase YES: ') == 'YES'):
                if (raw_input('\nType YES to install Pidgin with OTR: ') == 'YES'):
                    yum_Pidgin()
                    yum_Pidgin_OTR()
                yum_Python_Qt4()
                yum_Python_Serial()
                yum_install_Wget()
                SetSerialPermissions(raw_input("Type name of the user that will be running TFC (this will add the user to dialout group): "))
                get_NH_script()
                
                os.system('clear')
                print '\nNH install script completed\nRebooting system in 20 seconds. If you don\'t want to restart now, press CTRL+C'
                try:
                    time.sleep(20)
                    reboot()
                except KeyboardInterrupt:
                    print "\n\nReboot aborted, exiting. (You may need to restart your NH for NH.py to work correctly)\n"
                    exit()
            else:
                continue



    #Insecure testing mode with standalone computers
        if (selection == 9):
            os.system('clear')
            printLocalTesterWarning()
            if (raw_input('\nTO VERIFY THAT YOU UNDERSTAND RISKS,\nTYPE IN UPPERCASE \'INSECURE\': ') == 'INSECURE'):
                os.system('clear')
                if (raw_input('\nType YES to install Pidgin with OTR: ') == 'YES'):
                    install_Pidgin()
                    install_Pidgin_OTR()

                # WARNING! THE FOLLOWING KEYGEN IS ONLY INTENDED FOR TESTING TFC FEAETURES WITH VARYING SIZE GROUPS.
                # THIS KEYGEN GENERATES KEYFILES FOR N SIZED GROUPS. FOR EACH USER, ALL KEYS FOR EACH USER ARE 
                # COPIED INTO FOLDER NAMES AFTER THEIR XMPP ACCOUNT. ALL USER HAS TO DO, IS COPY THE FILES
                # IN THAT FOLDER TO SAME DIRECTORY WHERE THE KEYS OF USER ARE.

                #Specify global keyfile size in megabytes              
                megabytes = 2

                install_Python_Serial()
                install_Python_Qt4()
                install_SecureDelete()
                pyCrypto_Install()
                install_Python_pip()
                pip_salsa20()
                pip_twofish()
                userArray = []
                while True:
                    print ''
                    userC = raw_input('Enter XMPP account for user, or press Enter to create keys: ')
                    if (userC == ''):
                        break
                    userArray.append(userC)


                for user1 in userArray:
                    print 'Generating folder, downloading TFC program and generating local keys for user ' + user1
                    subprocess.Popen('mkdir ' + user1, shell=True).wait()

                    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/Tx.py', shell=True).wait()
                    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/Rx.py', shell=True).wait()
                    subprocess.Popen('wget https://raw.githubusercontent.com/maqp/tfc-cev/master/NH.py', shell=True).wait()

                    changeToLocal('Tx.py')
                    changeToLocal('Rx.py')
                    changeToLocal('NH.py')

                    subprocess.Popen('mv Tx.py ' + user1 + '/', shell=True).wait()
                    subprocess.Popen('mv Rx.py ' + user1 + '/', shell=True).wait()
                    subprocess.Popen('mv NH.py ' + user1 + '/', shell=True).wait()

                    create_keyfile('tx.local.e')
                    subprocess.Popen('cp tx.local.e rx.local.e', shell=True).wait()
                    subprocess.Popen('mv tx.local.e ' + user1 + '/', shell=True).wait()
                    subprocess.Popen('mv rx.local.e ' + user1 + '/', shell=True).wait()
                    time.sleep(0.5)
                print 'Done.'

                for user1 in userArray:
                    print 'Now creating keys for user: ' + user1
                    for user2 in userArray:
                        if (user1 != user2):
                            create_keyfile('tx.' + user1 + '.e')
                            subprocess.Popen('cp tx.' + user1 + '.e ' + 'me.' + user1 + '.e', shell=True).wait()
                            subprocess.Popen('cp tx.' + user1 + '.e ' + 'rx.' + user2 + '.e', shell=True).wait()
                            subprocess.Popen('mv tx.' + user1 + '.e ' + user2 + '/', shell=True).wait()
                            subprocess.Popen('mv me.' + user1 + '.e ' + user2 + '/', shell=True).wait()
                            subprocess.Popen('mv rx.' + user2 + '.e ' + user1 + '/', shell=True).wait()
                            time.sleep(0.5)
                    else:
                        continue

                os.system('clear')
                print "All files created succesfully.\n"
                print "If you want to try TFC out with your friends,\nThe application with all necessary files is in folder respective to their XMPP-address.\n"
                print '\nNote that you can remove the pycrypto-master folder if you\'re not going to audit the library. '
                exit()
            else:
                continue

    except ValueError:
        continue
    except IndexError:
        continue




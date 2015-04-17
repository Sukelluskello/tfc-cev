#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-CEV (Cascading Encryption Version) || tfcCEVinstaller.py
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
#                                 IMPORTS                            #
######################################################################

import os
import subprocess
import time

source = 'https://raw.githubusercontent.com/maqp/tfc-cev/master/'

######################################################################
#                             APT COMMANDS                           #
######################################################################

def update_system():
    cmd('Updating system',                       'sudo apt-get --yes update')


def install_Python_Serial():
    cmd('Installing Python-serial',              'sudo apt-get --yes install python-serial')


def install_Python_Qt4():
    cmd('Installing Python QT4',                 'sudo apt-get --yes install python-qt4')


def install_Python_pip():
    cmd('Installing Python pip',                 'sudo apt-get --yes install python-pip')


def install_SecureDelete():
    cmd('Installing Secure Delete',              'sudo apt-get --yes install secure-delete')


def install_Ent():
    cmd('Installing Ent entropy analysis suite', 'sudo apt-get --yes install ent')


def install_Pidgin():
    cmd('Installing Pidgin',                     'sudo apt-get --yes install pidgin')


def install_Pidgin_OTR():
    cmd('Installing Pidgin OTR',                 'sudo apt-get --yes install pidgin-otr')


######################################################################
#                            ZYPPER COMMANDS                         #
######################################################################

def zypper_Pidgin():
    cmd('Installing Pidgin',                     'sudo zypper install pidgin')


def zypper_Pidgin_OTR():
    cmd('Installing Pidgin OTR',                 'sudo zypper install pidgin-otr')


def zypper_Python_Serial():
    cmd('Installing Python-serial',              'sudo zypper install python-serial')


def zypper_Python_Qt4():
    cmd('Installing Python QT4',                 'sudo zypper install python-qt4')


######################################################################
#                             PIP COMMANDS                           #
######################################################################

def pip_salsa20():
    cmd('Installing Salsa20 crypto-library',     'sudo pip install salsa20')


def pip_twofish():
    cmd('Installing Twofish crypto-library',     'sudo pip install twofish')


######################################################################
#                              YUM COMMANDS                          #
######################################################################

def yum_Pidgin():
    cmd('Installing Pidgin',                     'sudo yum install pidgin')


def yum_Pidgin_OTR():
    cmd('Installing Pidgin OTR',                 'sudo yum install pidgin-otr')


def yum_install_Wget():
    cmd('Installing Wget',                       'sudo yum install wget')


def yum_Python_Serial():
    cmd('Installing Python-serial',              'sudo yum install pyserial')


def yum_Python_Qt4():
    cmd('Installing Python QT4',                 'sudo yum install pyqt4')


######################################################################
#                      FILE CONTENT CONFIGURING                      #
######################################################################

def rasp_cmdline():

    # Edit /boot/cmdline.txt to enable serial port for user (phase 1/2).
    print "\nEditing file 'cmdline.txt'\n"

    with open('/boot/cmdline.txt') as f:
        line = f.readline()
        line = line.replace(' console=ttyAMA0,115200 kgdboc=ttyAMA0,115200', '')

    with open('/boot/cmdline.txt', 'w+') as f:
        f.write(line)


def rasp_inittab():

    # Edit /etc/inittab to enable serial port for user (phase 2/2).
    print "\nEditing file 'inittab'\n"

    with open('/etc/inittab') as f:
        contents     = f.read()
        rep_contents = contents.replace('T0:23:respawn:/sbin/getty -L ttyAMA0 115200 vt100',
                                        '#T0:23:respawn:/sbin/getty -L ttyAMA0 115200 vt100')

    with open('/etc/inittab', 'w+') as f:
        f.write(rep_contents)


def serial_config(script_name):

    # Configure serial port of Tx.py/Rx.py for USB adapters.
    print "\nConfiguring serial interfaces of '" + script_name + "'\n"

    with open(script_name) as f:
        contents = f.read()
        contents = contents.replace("'/dev/ttyAMA0'", "'/dev/ttyUSB0'")

    with open(script_name, 'w+') as f:
        f.write(contents)


def changeToLocal(file_name):

    # Configure Tx/Rx/NH.py local_testing boolean to True.
    print "\nChanging boolean 'local_testing' of file '%s' to 'True'" % file_name

    with open(file_name) as f:
        contents = f.read()
        contents = contents.replace('local_testing = False', 'local_testing = True\n')

    with open(file_name, 'w+') as f:
        f.write(contents)


######################################################################
#                        FILE HASH VERIFICATION                      #
######################################################################

hash_tx = '9eb4d254d45797da87e14f4cea8b2a3d3eb29eac340946b90beda63605773f9c3dec6ded8c5ca545db500949e33b10948f97e8e2fc9d591ac8d321fba1287e68'
hash_gk = 'ceee5155f1979739977d63a76f412cda806ea6c3f2cd8f8fb7a5aa6704df0cc4582b27552b3494132dd076262f03264c0054d1bade2249d70976f6ef0b2b0e49'
hash_ge = '6d8ce0d3d1ff7f726b575acbf6218a7aaf2625c34143f3a0c6e6d30d23d27496fd95bcccbf29dfc829df03d826decbdbc51c6d3cc3976e37d87f4970b23171c3'
hash_vn = 'ca694bb571a5bcb6a3efe9e964e7ccc8db00e368dea59e6ddc22959392ebb07935cc83394aebcbf23be4cf823fbc0b941532986d74ade1e63e478b8e256a0236'
hash_rx = '6088fc2aade200b732e3ee9de0f28e538a26af4498091aab972cbc996b6b46a6115f72e2558670f1495adad01c3dee8ae2c8d835699d472cc5d5a0e590575e85'
hash_nh = 'd0462117d3499bd90e52190fea4d62b916403b4603be181647ba7961b0e013511b52e2ef5a8aedbaa718d14fcd194a648ecec7061846ab3718efd8316546cf41'


def check_file_hash(filename, file_hash):
    """
    Verify that SHA512 hash of file matches the one in installer.

    WARNING! Unless you can verify the origin of this intaller,
    you can NOT trust the hashes written here. They only protect
    against unintentional transmission errors, NOT against malicious
    actor. Please search the concept online, locate the original
    project, orignal developer and obtain developer's public PGP key
    from key server and verify this installer using it.

    --------------------------------------------------------------------------
    No practical MITM-attack free way exists to verify installer / public key.
    --------------------------------------------------------------------------

    Downloading the installer through TLS-encrypted Github website is NOT
    a guarantee that a state adversary could not edit the downloaded source
    code on the fly with great ease.

    The program depends on fact the user understands how TFC should work as a
    concept: That way user who reads the program code can evaluate what it does
    and ensure no covert functionality / back doors exist in the software.

    :param filename:  File to be hashed
    :param file_hash: The hash that this installer claims is the correct one.
    :return:
    """

    subprocess.Popen('sha512sum %s > tfc_sha512_hash_f' % filename, shell=True).wait()

    with open('tfc_sha512_hash_f') as f:
        f_hash = f.readline()
        f_hash = f_hash.strip('\n')[:-(len(filename) +2)]

    # Remove file with hash
    os.remove('tfc_sha512_hash_f')

    if f_hash != file_hash:
        os.system('clear')
        print 'CRITICAL ERROR: SHA512 hash of %s was incorrect. \n' \
              'This might indicate TLS-MITM attack or deprecated tfcCEVinstaller.' % filename
        exit()


######################################################################
#                    DOWNLOAD PROGRAMS / LIBRARIES                   #
######################################################################

def get_tx_script():
    cmd('Downloading Tx.py (TxM)', 'wget ' + source + 'Tx.py')
    check_file_hash('Tx.py',        hash_tx)


def get_gk_script():
    cmd('Downloading genKey.py (TxM)', 'wget ' + source + 'genKey.py')
    check_file_hash('genKey.py',    hash_gk)


def get_ge_script():
    cmd('Downloading getEntropy.c (TxM)', 'wget ' + source + 'getEntropy.c')
    check_file_hash('getEntropy.c', hash_ge)


def get_de_script():
    cmd('Downloading deskew.c (TxM)', 'wget ' + source + 'deskew.c')
    check_file_hash('deskew.c',     hash_vn)


def get_TxM_scripts():
    get_tx_script()
    get_gk_script()
    get_ge_script()
    get_de_script()


def get_rx_script():
    cmd('Downloading Rx.py (RxM)','wget ' + source + 'Rx.py')
    check_file_hash('Rx.py',        hash_rx)


def get_nh_script():
    cmd('Downloading NH.py (NH)','wget ' + source + 'NH.py')
    check_file_hash('NH.py',        hash_nh)

######################################################################
#                             MISC FUNCTIONS                         #
######################################################################

def pyCrypto_Install():

    appRdir = os.getcwd()

    cmd('Installing Python-dev',                 'sudo apt-get --yes install python-dev')

    cmd('Downloading PyCrypto Library',          'wget https://github.com/dlitz/pycrypto/archive/master.zip')

    cmd('Unzipping PyCrypto Library',            'unzip master.zip')

    os.chdir('pycrypto-master/')

    cmd('Installing PyCrypto Library',           'sudo python setup.py install')

    os.chdir(appRdir)

    cmd('Removing master.zip',                   'rm master.zip')


######################################################################
#                             MISC FUNCTIONS                         #
######################################################################

def cmd(message, command):
    print '\n%s\n' % message
    subprocess.Popen(command, shell=True).wait()
    return None

def c_program_compile():
    cmd('Compiling getEntropy.c',                'sudo gcc -Wall -O getEntropy.c -o getEntropy')
    cmd('Compiling deskew.c',                    'sudo gcc -Wall -O deskew.c -o deskew')


def c_program_permissions():
    print '\n compiled C-programs\n'
    cmd('Enabling permissions for getEntropy',   'sudo chmod a+x getEntropy')
    cmd('Enabling permissions for deskew',       'sudo chmod a+x deskew')


def create_keyfile(name):
    import binascii

    with open(name, 'w+') as f:
        for a in range(4):
            f.write('%s\n' % binascii.hexlify(os.urandom(32)))


def printLocalTesterWarning():
    print 'WARNING! YOU HAVE SELECTED THE LOCAL TESTING VERSION OF TFC! THIS '      \
          'VERSION IS INTENDED ONLY FOR TRYING OUT THE FEATURES AND STABILITY OF '  \
          'THE SYSTEM. IN THIS CONFIGURATION, THE ENCRYPTION KEYS ARE CREATED, '    \
          'STORED AND HANDLED ON NETWORK-CONNECTED COMPUTER, SO ANYONE WHO BREAKS ' \
          'IN TO YOUR COMPUTER BY EXPLOITING A KNOWN OR UNKNOWN VULNERABILITY ,'    \
          'CAN DECRYPT AND/OR FORGE ALL MESSAGES YOU SEND AND RECEIVE EFFORTLESSLY!'


def print_header():
    print 'TFC-CEV || ' + version + ' || tfcCEVinstaller.py'
    print '''
Select configuration that matches your OS:

   TxM
      1.  Raspbian (Run installer as superuser)

      2.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian)

   RxM
      3.  Raspbian (Run installer as superuser)

      4.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian)

    NH
      5.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian)

      6.  Tails

      7.  OpenSUSE

      8.  Fedora

    Local Testing (insecure)
      9.  Ubuntu
          Kubuntu
          Linux Mint (Ubuntu/Debian).\n'''


def printLocalTesterWarning():
    print '\n                             WARNING!                         \n' \
          '  YOU HAVE SELECTED THE LOCAL TESTING CONFIGURATION FOR TFC!    \n' \
          '  THIS VERSION IS INTENDED ONLY FOR TRYING OUT THE FEATURES AND \n' \
          '  STABILITY OF THE SYSTEM. IN THIS CONFIGURATION, THE ENCRYPTION\n' \
          '  KEYS ARE GENERATED, STORED AND HANDLED ON NETWORK-CONNECTED   \n' \
          '  COMPUTER, SO ANYONE WHO BREAKS IN TO IT BY EXPLOITING A KNOWN \n' \
          '  (OR UNKNOWN ZERO DAY) VULNERABILITY CAN DECRYPT AND/OR FORGE  \n' \
          '  EVERY MESSAGES YOU SEND AND RECEIVE!'


def SetSerialPermissions(username=''):
    if username == '':
        username = raw_input('Type name of the user that will be running TFC (this will add the user to dialout group): ')

    cmd("Adding user '%s' to dialout group to enable serial device use" % username, 'sudo gpasswd --add %s dialout' % username)


def yes(prompt):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked
    :return:       True if user types y(es), False if user types n(o).
    """

    os.system('clear')
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
#                            CONFIGURATIONS                          #
######################################################################

# TxM
def rapi_txm():
    if yes('Install TxM configuration for Raspbian?'):

        update_system()
        install_SecureDelete()
        get_TxM_scripts()
        c_program_compile()
        c_program_permissions()
        install_Python_Serial()
        rasp_cmdline()
        rasp_inittab()
        pyCrypto_Install()
        install_Python_pip()
        pip_salsa20()
        pip_twofish()

        os.system('clear')
        print ('\nTxM install script completed   \n'
               'Reboot the system before running.\n'
               'The pycrypto-master folder was   \n'
               'left to allow auditing purposes. \n')
        exit()

    else:
        return None


def ubuntu_txm():
    if yes('Install TxM configuration for Ubuntu / Linux Mint?'):

        update_system()
        install_SecureDelete()
        get_TxM_scripts()
        c_program_compile()
        c_program_permissions()
        install_Python_Serial()
        serial_config('Tx.py')
        SetSerialPermissions()
        pyCrypto_Install()
        install_Python_pip()
        pip_salsa20()
        pip_twofish()

        os.system('clear')
        print ('\nTxM install script completed   \n'
               'Reboot the system before running.\n'
               'The pycrypto-master folder was   \n'
               'left to allow auditing purposes. \n')
        exit()

    else:
        return None


# RxM
def rapi_rxm():
    if yes('Install RxM configuration for Raspbian?'):

        update_system()
        install_SecureDelete()
        get_rx_script()
        install_Python_Serial()
        rasp_cmdline()
        rasp_inittab()
        pyCrypto_Install()
        install_Python_pip()
        pip_salsa20()
        pip_twofish()

        os.system('clear')
        print ('\nRxM install script completed   \n'
               'Reboot the system before running.\n'
               'The pycrypto-master folder was   \n'
               'left to allow auditing purposes. \n')
        exit()

    else:
        return None


def ubuntu_rxm():
    if yes('Install RxM configuration for Ubuntu / Linux Mint?'):

        update_system()
        install_SecureDelete()
        get_rx_script()
        install_Python_Serial()
        serial_config('Rx.py')
        SetSerialPermissions()
        pyCrypto_Install()
        install_Python_pip()
        pip_salsa20()
        pip_twofish()

        os.system('clear')
        print ('\nRxM install script completed   \n'
               'Reboot the system before running.\n'
               'The pycrypto-master folder was   \n'
               'left to allow auditing purposes. \n')
        exit()

    else:
        return None


# NH
def ubuntu_nh():
    if yes('Install NH configuration for Ubuntu / Linux Mint?'):

        update_system()

        if yes('\n  Install Pidgin with OTR-plugin?'):
            install_Pidgin()
            install_Pidgin_OTR()

        install_Python_Qt4()
        install_Python_Serial()
        get_nh_script()
        SetSerialPermissions()


        os.system('clear')
        print ('\nNH install script completed    \n'
               'Reboot the system before running.\n'
               'The pycrypto-master folder was   \n'
               'left to allow auditing purposes. \n')
        exit()

    else:
        return None

def tails_nh():
    if yes('Install NH configuration for Tails LiveCD / USB?'):

        get_nh_script()
        SetSerialPermissions('amnesia')

        os.system('clear')
        print '\nNH install script completed. To launch NH, type below' \
              '\n                   python NH.py'
        #        amnesia@amnesia:~$ <-- space left for default username and hostname.
        exit()

    else:
        return None


def opensuse_nh():
    if yes('Install NH configuration for OpenSUSE?'):

        if yes('\n  Install Pidgin with OTR-plugin?'):
            zypper_Pidgin()
            zypper_Pidgin_OTR()

        zypper_Python_Qt4()
        zypper_Python_Serial()
        get_nh_script()
        SetSerialPermissions()

        os.system('clear')
        print ('\nNH install script completed    \n'
               'Reboot the system before running.\n'
               'The pycrypto-master folder was   \n'
               'left to allow auditing purposes. \n')
        exit()

    else:
        return None

def fedora_nh():
    if yes('Install NH configuration for OpenSUSE?'):

        if yes('\n  Install Pidgin with OTR-plugin?'):
            yum_Pidgin()
            yum_Pidgin_OTR()

        yum_Python_Qt4()
        yum_Python_Serial()
        yum_install_Wget()
        get_nh_script()
        SetSerialPermissions()

        os.system('clear')
        print ('\nNH install script completed    \n'
               'Reboot the system before running.\n'
               'The pycrypto-master folder was   \n'
               'left to allow auditing purposes. \n')
        exit()

    else:
        return None


# Local testing
def local_testing():
    os.system('clear')

    printLocalTesterWarning()
    if raw_input("\n  IF YOU UNDERSTAND RISKS, TYPE 'INSECURE': ") == 'INSECURE':

        os.system('clear')

        if yes('\n  Install Pidgin with OTR-plugin?'):
            install_Pidgin()
            install_Pidgin_OTR()

        install_Python_Serial()
        install_Python_Qt4()
        install_SecureDelete()
        pyCrypto_Install()
        install_Python_pip()
        pip_salsa20()
        pip_twofish()

        userArray = []

        os.system('clear')

        print ('\n  Installing dependencies completed. The system will  \n'
               '  now ask you to enter the XMPP-addresses that will be  \n'
               '  participating in testing  to generate local test      \n'
               '  folders for each user. If you have already received a \n'
               '  local test folder, you can press enter to close the   \n'
               '  installer and start the Tx.py, Rx.py and NH.py.     \n\n'
               '  Enter all XMPP-accounts used in testing and then      \n'
               '  enter empty input by pressing Enter to create files:\n')

        while True:

            userC = raw_input('  > ')
            if userC == '':
                break
            userArray.append(userC)

        for user1 in userArray:
            print '\nCreating folder, downloading TFC program and generating local keys for user %s\n' % user1
            subprocess.Popen('mkdir ' + user1, shell=True).wait()

            get_tx_script()
            get_rx_script()
            get_nh_script()
            subprocess.Popen('wget ' + source + 'tfcCEVinstaller.py -O tfcInstaller.py', shell=True).wait()

            changeToLocal('Tx.py')
            changeToLocal('Rx.py')
            changeToLocal('NH.py')

            subprocess.Popen('mv Tx.py %s/'              % user1, shell=True).wait()
            subprocess.Popen('mv Rx.py %s/'              % user1, shell=True).wait()
            subprocess.Popen('mv NH.py %s/'              % user1, shell=True).wait()
            subprocess.Popen("mv tfcInstaller.py '%s/'"  % user1, shell=True).wait()

            create_keyfile('tx.local.e')
            subprocess.Popen('cp tx.local.e rx.local.e',    shell=True).wait()
            subprocess.Popen("mv tx.local.e '%s/'" % user1, shell=True).wait()
            subprocess.Popen("mv rx.local.e '%s/'" % user1, shell=True).wait()

            time.sleep(0.2)

        print 'Done.'

        for user1 in userArray:
            print 'Creating keys for user: ' + user1
            for user2 in userArray:
                if user1 != user2:
                    create_keyfile('tx.%s.e' % user1)
                    subprocess.Popen('cp tx.%s.e me.%s.e' % (user1, user1), shell=True).wait()
                    subprocess.Popen('cp tx.%s.e rx.%s.e' % (user1, user2), shell=True).wait()
                    subprocess.Popen("mv tx.%s.e '%s'/"   % (user1, user2), shell=True).wait()
                    subprocess.Popen("mv me.%s.e '%s'/"   % (user1, user2), shell=True).wait()
                    subprocess.Popen("mv rx.%s.e '%s'/"   % (user2, user1), shell=True).wait()
                    time.sleep(0.5)
            else:
                continue

        os.system('clear')
        print ('\n  Test folders named after each user generated succesfully.\n'
               '  Before each user can run their test version of TFC, they   \n'
               '  must run the bundled tfcInstaller.py and also choose the   \n'
               '  installation configuration 9. When the installer has       \n'
               '  installed dependencies, the user is ready to run the       \n'
               '  Tx.py, Rx.py and NH.py. Note that other users don\'t have  \n'
               '  to create their own keyfiles for insecure testing.       \n\n'
               '  The pycrypto-master folder in tfcCEVInstaller.py directory \n'
               '  is only needed for auditing the pyCrypto AES-library.      \n')

        print '  Exiting tfcCEVinstaller.py\n'
        exit()

    else:
        return None


######################################################################
#                              MAIN LOOP                             #
######################################################################

while True:
    try:
        os.system('clear')
        print_header()
        selection = int(raw_input('1..9: '))

        # Raspberry Pi TxM
        if selection == 1:
            rapi_txm()
        # Ubuntu TxM
        if selection == 2:
            ubuntu_txm()

        # Raspberry Pi TxM
        if selection == 3:
            rapi_rxm()

        # Ubuntu RxN
        if selection == 4:
            ubuntu_rxm()

        # Ubuntu NH
        if selection == 5:
            ubuntu_nh()

        # Tails NH
        if selection == 6:
            tails_nh()

        # OpenSUSE NH
        if selection == 7:
            opensuse_nh()

        # Fedora NH
        if selection == 8:
            fedora_nh()

        # Local testing
        if selection == 9:
            local_testing()

    except ValueError:
        continue
    except IndexError:
        continue
    except KeyboardInterrupt:
        print '\n\nExiting tfcCEVinstaller.py\n'
        exit()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-CEV (Cascading Encryption Version) || NH.py
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
disp_t_fmt  = '%Y-%m-%d / %H:%M:%S'  # Format of timestamps when displaying messages.

verbose         = False              # When enabled, prints received messages.

print_ratio     = False              # When enabled, prints the ratio of commands and
                                     # messages (for constant transmission mode).

# Security settings
emergency_exit  = False             # When enabled, kills all python
                                     # programs and Pidgin when alerted.

# Developer tools
debugging       = False              # Set true to enable verbose messaging
                                     # about inner operations in NH.py.

# Local testing mode: enabled when testing TFC on single computer.
local_testing = False


# Serial settings
serial_baudrate = 9600               # Serial device speed.
txm_interface   = '/dev/ttyUSB0'     # Serial interface that connects to TxM.
rxm_interface   = '/dev/ttyUSB1'     # Serial interface that connects to RxM.


######################################################################
#                                 IMPORTS                            #
######################################################################

import os
import datetime
import dbus
import sys
import serial
import subprocess
import zlib
from multiprocessing  import Process, Queue
from PyQt4.QtGui      import QApplication
from dbus.mainloop.qt import DBusQtMainLoop
from time             import sleep


######################################################################
#                               FUNCTIONS                            #
######################################################################

def crc32(content):
    """
    Calculate CRC32 checksum of input.

    :param content: Input checksum is calculated from.
    :return:        CRC32 checksum of input.
    """

    return str(hex(zlib.crc32(content)))


# LOCAL TESTING
def load_msg():
    """
    Load message from file when local testing is enabled.

    :return: Loaded message.
    """

    with open('TxOutput') as f:
        message = f.readline()

    if debugging and (message != ''):
        print 'M(load_msg): Loaded following message \n%s\n' % message

    return message


def clear_local_msg():
    """
    Clear the 'TxOutput' file.

    :return: None.
    """

    if local_testing:
        open('TxOutput', 'w+').close()

    return None


def write_msg(message):
    """
    Write message to file when local testing is enabled.

    :param message: Message to be written.
    :return:        None.
    """
    
    with open('NHoutput', 'w+') as f:
        f.write(message)

    return None


def ratio(commands, messages):
    """
    Prints the ratio between sent commands and messages for session.

    :param commands: Total number of commands.
    :param messages: Total number of messages.
    :return:         Ratio between commands and messages
    """

    ratio1 = commands / messages * 1.0
    ratio2 = messages / commands * 1.0
    return str(ratio1) + ' : ' + str(ratio2)


class DBus_MsgReceiver():

    def __init__(self, received_msg):
        self.answer = received_msg
        bus_loop    = DBusQtMainLoop(set_as_default=True)
        self.bus    = dbus.SessionBus()
        self.bus.add_signal_receiver(self.receiveFunc, dbus_interface='im.pidgin.purple.PurpleInterface', signal_name='ReceivedImMsg')

    def receiveFunc(self, account, sender, message, conversation, flags):

        purple_service   = 'im.pidgin.purple.PurpleService'
        purple_object    = '/im/pidgin/purple/PurpleObject'
        purple_interface = 'im.pidgin.purple.PurpleInterface'

        obj              = self.bus.get_object(purple_service, purple_object)
        purple           = dbus.Interface(obj, purple_interface)
        conv_im          = purple.PurpleConvIm(conversation)

        purple.PurpleConvImSend(conv_im, self.answer)

        xmpp             = (sender.split('/'))[0]
        crc              = crc32(message[5:])
        split_line       = message.split('|')
        msg_content      = str(split_line[0])

        if msg_content.startswith('?TFC_'):
            timestamp = datetime.datetime.now().strftime(disp_t_fmt)
            print '%s  Received encrypted message from  %s' % (timestamp, xmpp)

            if verbose:
                print '\nmessage was:\n%s\n'    % message

            sq.put('<mesg>rx.%s~%s~%s\n' % (xmpp, message[5:], crc))
        else:
            pass

######################################################################
#                               THREADS                              #
######################################################################


def serial_port_sender():
    """
    Load message from queue sq and write it to file / serial port.

    :return: None
    """

    while True:
        payload = sq.get()

        if local_testing:
            write_msg(payload)
        else:
            portToRxM.write(payload)

    return None


def network_transmitter():
    """
    Process that outputs messages via dBus to Pidgin.

    :return: No return.
    """

    purple_service = 'im.pidgin.purple.PurpleService'
    purple_object  = '/im/pidgin/purple/PurpleObject'
    bus            = dbus.SessionBus()
    pidgin_proxy   = bus.get_object(purple_service, purple_object)
    purple         = dbus.Interface(pidgin_proxy, purple_service)
    account_id     = purple.PurpleAccountsGetAllActive()[0]
    account_name   = purple.PurpleAccountGetUsername(account_id)[:-1]

    print 'Active account: %s\n' % account_name

    class DBus_MsgSender:

        def __init__(self, contact_id):
            purple_service            = 'im.pidgin.purple.PurpleService'
            purple_object             = '/im/pidgin/purple/PurpleObject'
            self.contact_id           = contact_id
            bus                       = dbus.SessionBus()
            pidgin_proxy              = bus.get_object(purple_service, purple_object)
            self.purple               = dbus.Interface(pidgin_proxy, purple_service)
            account_id                = self.purple.PurpleAccountsGetAllActive()[0]
            self.contact_conversation = self.purple.PurpleConversationNew(1, account_id, self.contact_id)
            self.contact_im           = self.purple.PurpleConvIm(self.contact_conversation)

        def sender(self):
            self.purple.PurpleConvImSend(self.contact_im, msg_content)

        def clearHistory(self):
            self.purple.PurpleConversationClearMessageHistory(self.contact_conversation)

    o = ''
    commands = 1.0
    messages = 1.0

    while True:
        try:
            msg_content = ''
            rcd_pkg     = ''

            if local_testing:
                while not rcd_pkg.endswith('\n'):
                    sleep(0.1)
                    try:
                        rcd_pkg = load_msg()
                    except IOError:
                        continue
            else:
                while not rcd_pkg.endswith('\n'):
                    sleep(0.01)
                    rcd_pkg = portToTxM.readline()

            if rcd_pkg == '':
                clear_local_msg()
                continue

            # Emergency exit.
            elif rcd_pkg.startswith('EXITTFC'):

                sq.put(rcd_pkg + '\n')
                os.system('clear')
                clear_local_msg()

                if emergency_exit:
                    subprocess.Popen('killall pidgin', shell=True).wait()

                sleep(0.1)                                                 # Sleep allows local Rx.py some time to exit cleanly
                subprocess.Popen(    'killall python', shell=True).wait()  # Note that this kills all python programs, not only NH.py

            # Clear screens.
            elif rcd_pkg.startswith('CLEARSCREEN'):
                timestamp = datetime.datetime.now().strftime(disp_t_fmt)
                print '%s      Sent plaintext command to    RxM' % timestamp

                xmpp = rcd_pkg.split(' ')[1]
                xmpp = xmpp.strip('\n')

                sq.put(rcd_pkg + '\n')
                os.system('clear')

                o = DBus_MsgSender(xmpp)
                o.clearHistory()

            # Relay command to RxM.
            elif rcd_pkg.startswith('<ctrl>'):
                rcd_pkg            = (rcd_pkg[6:]).strip('\n')
                msg_content, crc_p = rcd_pkg.split('~')
                crc_c              = crc32(msg_content)

                if crc_c != crc_p:
                    print '\nCRC checksum error: Command was not forwarded to RxM\n' \
                          'or recipient. Please try sending the message again.\n'    \
                          'If error persists, check the batteries of TxM data diode.\n\n'
                    clear_local_msg()
                    continue

                if debugging: print 'network_transmitter: Wrote <ctrl>%s~%s to sq.\n' % (msg_content, crc_c)
                sq.put(                                        '<ctrl>%s~%s\n'        % (msg_content, crc_c))

                timestamp = datetime.datetime.now().strftime(disp_t_fmt)
                commands += 1
                ratiostr  = '' if not print_ratio else '              ratio   %s'     % ratio(commands, messages)
                print '%s      Sent encrypted command to    RxM             %s'       % (timestamp, ratiostr)

                if verbose: print 'Command was:\n%s\n' % msg_content


            # Relay message to RxM and Pidgin.
            elif rcd_pkg.startswith('<mesg>'):
                message                  = (rcd_pkg[6:]).strip('\n')
                xmpp, msg_content, crc_p = message.split('~')
                crc_c                    = crc32(msg_content[5:])

                if crc_c != crc_p:
                    print '\nCRC failed: Message was not forwarded to RxM or contact.\n' \
                          'Please try sending the message again from your TxM.       \n' \
                          'If this error repeats check the TxM data diode batteries. \n'
                    continue

                if debugging: print "network_transmitter: Wrote '<mesg>me.%s~%s~%s' to sq\n"  % (xmpp, msg_content[5:], crc_p)
                sq.put(                                         '<mesg>me.%s~%s~%s\n'         % (xmpp, msg_content[5:], crc_p))

                o = DBus_MsgSender(xmpp)
                o.sender()

                timestamp = datetime.datetime.now().strftime(disp_t_fmt)
                messages += 1
                ratiostr  = '' if not print_ratio else ((30 - len(xmpp)) * ' ' + 'ratio   %s' % ratio(commands, messages))
                print '%s      Sent encrypted message to    %s%s'                             % (timestamp, xmpp, ratiostr)

                if verbose: print 'Message was:\n%s\n' % msg_content

            else:
                print '\nError: Received packet with malformed header.\n'

            clear_local_msg()

        except OSError:
            continue

        except dbus.exceptions.DBusException:
            print 'WARNING! DBus did not initiate properly.\nCheck that Pidgin is running before running NH.py\n\n'
            continue


def network_receiver():
    """
    Process that receives messages from Pidgin.

    :return: No return.
    """

    app = QApplication(sys.argv)
    run = DBus_MsgReceiver('')
    app.exec_()


######################################################################
#                                MAIN                                #
######################################################################

# Set initial values.
flag       = ''
ifAssist   = ''

# If flip ('-f') flag is provided, flip serial devices.
try:
    if str(sys.argv[1]) == '-f':
        txm_interface, rxm_interface = rxm_interface, txm_interface
except IndexError:
    pass

# If local testing is disabled, initialize serial ports.
if not local_testing:
    try:
        portToTxM = serial.Serial(txm_interface, serial_baudrate, timeout=0.1)
        portToRxM = serial.Serial(rxm_interface, serial_baudrate, timeout=0.1)

    except serial.serialutil.SerialException:
        print '\nSerial interfaces are set incorrectly.\n'

# Clear local message files.
clear_local_msg()

# Initialize queue for messages.
sq = Queue()

# Print header.
os.system('clear')
print 'TFC-CEV %s || NH.py \n' % version

# Start processes.
ss = Process(target=serial_port_sender)
nt = Process(target=network_transmitter)
nr = Process(target=network_receiver)

ss.start()
nt.start()
nr.start()

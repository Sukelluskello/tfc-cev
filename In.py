#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-CEV (Cascading Encryption Version) || In.py
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


"""
 README
 This software is a simple tool that enables you to inject custom packets
 into RX.py's local testing temporary file. It somewhat simplifies the 
 manual penetration testing process. Be sure to enable injection mode on Rx.py:
 that way Rx.py will switch to read messages/commands from INoutput instead.

     1. Move In.py to local testing directory.

     2. Start Tx.py with local_testing boolean as True.

     3. Start NH.py with local_testing boolean as True
         You might want to comment out lines in NH.py to disable
         sending injection messages to random XMPP addresses.

            o = DBus_MsgSender(xmpp)  // line 283
            o.clearHistory()          // line 284

            o = DBus_MsgSender(xmpp)  // line 325
            o.sender()                // line 326
            
         You might also want to remove CRC checksum
         verification  from Rx.py by commenting out.
         
            if crc32(cmd_mac_line) != crc_pkg:      // lines 2211-2213
                packet_anomality('crc', 'command')
                continue

            if crc32(ct_mac_ln) != crc_pkg:         // lines 2281-2283
                packet_anomality('crc', 'message')
                continue
                                    
     4. Start Rx.py with local_testing and injection_testing boolean as True.

     5. Start In.py
         To inject, start by writing a message with Tx.py.

         In.py opens NHoutput with nano: edit the message.

         Send message with CTRL + <x>, <y>, <ENTER>.

         In.py shows the packet, reads the modified file and saves it as INoutput.

         Rx.py reads INoutput just as it would normally read NHoutput
         and act accordingly. Packet will be cleared after each use.

         Rinse and repeat. Happy hacking. (:

     Dev note: let me know if you can craft a packet that crashes Rx.py:
         oottela@cs.helsinki.fi

"""


import subprocess
import os
import time

def getPacket():
    with open("NHoutput") as f:
        contents = f.readline()
    return contents


def writePacket(contents):
    with open("INoutput", "w+") as f:
        f.write(contents+"\n")

try:
    while True:

        os.system('clear')
        print 'TFC Injection testing tool 0.5.4'

        while getPacket() == '':
           time.sleep(0.01) 
           continue

        subprocess.Popen('nano NHoutput', shell=True).wait()

        packet = getPacket()

        print "\nEdited packet:\n" + packet

        writePacket(packet)

        time.sleep(2)

except KeyboardInterrupt:

    os.system('clear')
    print '\nExiting In.py\n'

    exit()

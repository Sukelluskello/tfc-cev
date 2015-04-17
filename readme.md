<img align="right" src="https://cs.helsinki.fi/u/oottela/tfclogo.png" style="position: relative; top: 0; left: 0;">
 

###Tinfoil Chat CEV


TFC-CEV is a high assurance encryption plugin for Pidgin IM client, built on free and open source hardware and software. Secure by design implementation protects data in transit against [passive](https://en.wikipedia.org/wiki/Upstream_collection) and [active](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attacks as well as the end points against untasked targeted attacks practiced by TLAs such as the [NSA](https://firstlook.org/theintercept/2014/03/12/nsa-plans-infect-millions-computers-malware/), [GCHQ](http://www.wired.co.uk/news/archive/2014-03/13/nsa-turbine) and [BKA](http://ccc.de/en/updates/2011/staatstrojaner).

**Encryption** is done with cascaded set of symmetric ciphers: Keccak-CTR, XSalsa20, Twofish-CTR and AES-GCM have internally different structures: Attacker neeeds to have cyptanalytic attacks against all of them to decrypt messages. [Not secure enough?](https://github.com/maqp/tfc)

**Keys** are generated with an open circuit design hardware random number generator that feeds truly random (read: back-door free) entropy when generating the four independent 256-bit symmetric keys. Perfect forward secrecy is obtained by rotating keys through Keccak (SHA3) hash function after use. 

**Endpoints** are secured by separating encryption and decryption on two TCB-devides that interact with the network client through data-diode enforced unidirectional channels. Removing the bidirectional channel prevents exfiltration of keys and plaintexts with remote attacks regardless of existing zero-day vulnerabilities in the OS of TCBs.

###How it works

![](https://cs.helsinki.fi/u/oottela/tfc_graph.png)

In TFC, Alice enters her message into Tx.py running on her Transmitter Module (TxM), a TCB separated from network. Tx.py encrypts the message and signs the ciphertext. TxM then relays the packet to Network Handler (NH) through RS-232 interface and a data diode.

The NH.py script running on Alice's NH listens to packets from TxM's serial port, and forwards message to Pidgin via dbus IPC. A copy of the packet is also sent to her Receiver Module (RxM, another TCB separated from network) through RS-232 interface and a data diode, where the the ciphertext is authenticated, displayed and optionally also logged.

Pidgin sends the packet either directly or through Tor network to IM server, that then forwards it directly (or again through Tor) to Bob.

On the Bob's NH, the script NH.py receives Alice's packet from Pidgin via dbus and forwards it through RS-232 interface and another data diode to his RxM, where the ciphertext is authenticated, decrypted, displayed and optionally also logged. When the Bob responds, he will send the message using his TxM and in the end Alice reads the message from her RxM.


###Why keys can not be exfiltrated

1. The payload can reach RxM, but is unable to transmit anything back to NH.

2. The payload never reaches TxM since the device can only transmit.

3. The NH is assumed to be compromised, but unencrypted data never touches it.

![](https://cs.helsinki.fi/u/oottela/tfc_attacks.png)

The optical gap of the data diode (below) physically blocks back channels.

<img  src="https://cs.helsinki.fi/u/oottela/data_diode.png" align="center" width="74%" height="74%"/>

###Detailed information

Whitepaper: https://cs.helsinki.fi/u/oottela/tfc.pdf

Manual: https://cs.helsinki.fi/u/oottela/tfc-manual.pdf

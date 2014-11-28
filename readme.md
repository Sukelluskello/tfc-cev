Project Description:
--------------------

TFC-CEV is a high assurance encryption plugin for Pidgin IM client that combines free and open source hardware and software. Secure by design implementation provides a no-compromise layer that addresses automatable attacks used by intelligence agencies for mass surveillance:

1. Computationally secure **cascading** encryption ensures privacy and integrity of communication.

2. Hardware random number generator provides truly random entropy for encryption keys.

3. Data diodes provide hardware enforced unidirectional gateways that prevent exfiltration (theft) of plaintexts and encryption keys.

This project is an official fork of Tinfoil Chat (TFC-OTP), which uses information theoretically secure encryption and authentication.
Apart from different security claim, some commands and differences in UI, the whitepaper and manual are applicable for TFC-CEV:

Whitepaper: https://cs.helsinki.fi/u/oottela/tfc.pdf

Manual: https://cs.helsinki.fi/u/oottela/tfc-manual.pdf


TFC-CEV Features
----------------

**Encryption keys**

TFC-CEV uses a set of four independent hexadecimal keys. Each key has a length of 64 (256 bit strength).

**Please note that each key must be preshared face to face (e.g. on USB-thumb drive or on a piece of paper) between contacts. This is unfortunately the only MITM attack-free way. Never use insecure mediums such as telephone, email, or even end-to-end encrypted systems (PGP/OTR/ZRTP)! Each of these systems have lower security rating than TFC.**

Please note that reduced size of encryption key compared to TFC-OTP increases the risk, where if a malware compromises the TxM during OS installation, the keys might be exfiltrated along 1 to 128 packets.

Keyfiles are named in the same fashion as TFC-OTP; Do not mix files. Keep each version in their dedicated folder.

**Physical security**

TFC provides vastly more secure environment compared to traditional systems. It is the only one resistant against key exfiltration via 0-day exploits. Only way to steal encryption keys is by breaking into user's house, office etc. It's highly recommened to use a full-disc-encrypted device to store software and keys, and to operate the programs only with liveCD environment. Amnesic Linux distribution protects against persistent software keyloggers and on-screen keyboard against physical ones.

**Perfect forward secrecy**

This version of TFC provides perfect forward secrecy. This means

   a) All messages sent **before** physical key compromise remain private, unless recipient logs them.

   b) All messages sent **after** physical key compromise **can be decrypted by the adversary**.


**Deniablity**

This version of TFC provides limited deniability: Messages are not digitally signed, thus the recipient can't prove that it wasn't (s)he who crafted the messages. Due to 'loopbackless' nature of TFC, RxM of Bob can't inform TxM of Alice when it has received the message. Therefore, publishing MAC keys in similar fashion to OTR would destroy integrity of messages, since adversary might withold sent messages until it has received the MAC key; The adversary could then succeed in performing an existential forgery.


**Installation**

Please install the tool using tfcCEVinstaller.py by running following commands in terminal:

1. wget https://raw.githubusercontent.com/maqp/tfc-cev/master/tfcCEVinstaller.py
        
2. python tfcCEVinstaller.py

Standard operation of TFC-CEV requires users to use three separate computers. Using TFC in such configuration is of paramount importance. However, TFC-CEV has an installaltion configuration that allows it to be run on three separate terminals on a single network connected computer. This allows users to test the features and stability of TFC and exchange messages. Please remember, that this configuration can not be claimed to be high assurance.


**Polycipher components**

**Name**   | **Block/State size (bits)** | **Key size (bits)** | **Cipher type** | **Structure**                             |
---------- | --------------------------- | ------------------- | --------------- | ----------------------------------------- |
Keccak     | 1600                        | 256                 | Stream cipher   | Sponge function                           |
Salsa20    | 512                         | 256                 | Stream cipher   | 32-bit addition, XOR, rotation operations |
Twofish    | 128                         | 256                 | Block cipher    | Feistel network                           |
Rijndael   | 128                         | 256                 | Block cipher    | Substitution-permutation network          |

**Notes:**

Keccak   is the SHA3 standard. It is used as PRNG for the stream cipher.
Twofish  is an AES finalist, operated in randomized CTR-mode.
Salsa20  is part of EStream suite.
Rijndael is the AES standard, operated in GCM mode (randomized CTR + GMAC authentication).



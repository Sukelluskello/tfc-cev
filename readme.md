Project Description:
--------------------

(TFC-CEV) is a high assurance encryption plugin for Pidgin IM client that combines free and open source hardware and software. Secure by design implementation provides a no-compromise layer over the standard and OTR encrypted communication, that addresses automatable attacks used by intelligence agencies for mass surveillance:

1. Computationally secure **cascading** encryption ensures privacy and integrity of communication.

2. Hardware random number generator provides truly random entropy for encryption keys.

3. Data diodes provide hardware enforced unidirectional gateways that prevent exfiltration (theft) of plaintexts and encryption keys.

This project is an official fork of Tinfoil Chat TFC(-OTP), which uses information theoretically secure encryption and authentication.
Apart from different security claim, some commands and differences in UI, the whitepaper and manual are applicable for TFC-CEV:

Whitepaper: https://cs.helsinki.fi/u/oottela/tfc.pdf

Manual: https://cs.helsinki.fi/u/oottela/tfc-manual.pdf


TFC-CEV Features
----------------

**Encryption keys**

TFC-CEV uses a set of four hexadecimal keys. Each key has length of 64 (256 bits).

The three inner encryption keys should be generated using the HWRNG output, XOR'd with /dev/random
to ensure proper level of security. Fourth one is done so initally as well, but can later be generated
with manually authenticated Diffie-Hellman key exchange.

Please note that reduced size of encryption key compared to OTP increases the risk of malware compromising
TxM during OS installation, and keys might in theory be exfiltrated within 1 to 128 messages.

Keyfiles are named in the same fashion as OTP-TFC (don't mix files, keep the software in a dedicated folder!).

**Physical security**

TFC provides vastly more secure environment compared to traditional systems. It is the only one resistant
against key exfiltration via 0-day exploits. This means only way to steal keys is by breaking into users
house, office etc. It's highly recommened to use full-disc-encrypted storage for software and keys, and to operate
the program only with liveCD environment. Amnesic Linux distribution protects against software keyloggers and
on-screen keyboard against physical ones.


**Perfect forward secrecy**

This version of TFC provides users with perfect forward secrecy. This means

   a) All messages sent **before** physical key compromise remain private, unless recipient logs them.

   b) All messages sent **after** physical key compromise **can be decrypted unless you perform--**


**Ephemeral key exchange**

If you suspect your physical security has compromised, you can use Diffie-Hellman key exchange (DHE) to
share new encryption key. This key only affects the outermost layer, meaning if your physical security
has not been compromised, the discrete logarithm problem of DHE will not provide single computationally
weak link, that would compromise all keys. To obtain full security, it is important to make another exchange
and preferrable exhange all keys.

Please note that DHE key exchange is anonymous. This means you need to verify from who you have received
the public key. Verification is done manually by comparing hash of DH shared secret key. ONLY use channels where real
time editing is difficult, such as telephone conversation: Eavesdropping does not compromise DHE, only active alteration.
Never use only easy to compromise channels such as text based services, SMSs, IMs, even if they claim to be end-to-end encrypted.
Use of multiple channels is of course more secure as all of them need to be MITM attacked at the same time.

During hashing, users should enter a shared secret to salt the input. This way MITM-attacking adversary can not automatically derive the
hash from shared secret key. Instead, either sophisticated AI or human with knowledge of the shared secret is needed
to generate the correct hash. Please note, that the answer must be exactly correct for both users. Otherwise the derived hashes 
will be different and it looks like MITM attack is taking place, even if it actually isn't.

**Installation**

Please install the tool using tfcCEVinstaller.py by running

1. wget https://raw.githubusercontent.com/maqp/tfc-cev/master/tfcCEVinstaller.py
        
2. python tfcCEVinstaller.py


**Polycipher components**

**Name**   | **Block/State size (bits)** | **Key size (bits)** | **Cipher type** | **Structure**                             |
---------- | --------------------------- | ------------------- | --------------- | ----------------------------------------- |
Keccak     | 1600                        | 256                 | Stream cipher   | Sponge function                           |
Salsa20    | 512                         | 256                 | Stream cipher   | 32-bit addition, XOR, rotation operations |
Twofish    | 128                         | 256                 | Block cipher    | Feistel network                           |
Rijndael   | 128                         | 256                 | Block cipher    | Substitution-permutation network          |

**Notes:**

Keccak   is the SHA3 standard,  that is used as PRNG for the stream cipher.
Twofish  is an AES finalist, operated in randomized CTR-mode
Salsa20  is part of EStream suite.
Rijndael is the AES standard, operated in GCM mode (randomized CTR + GMAC authentication).



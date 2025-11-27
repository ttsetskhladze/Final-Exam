\# Task 2 – Secure File Exchange Using RSA + AES



\## 1. Overview



In this task I built a small secure file exchange between two people: \*\*Alice\*\* and \*\*Bob\*\*.  

The idea is to use \*\*hybrid encryption\*\*:



\- \*\*AES-256\*\* (symmetric encryption) to protect the file itself

\- \*\*RSA\*\* (asymmetric encryption) to protect the AES key



This follows the protocol we saw in Week 2 and Week 4: RSA is used for key exchange, and AES is used for fast data encryption.



---



\## 2. Roles and Files



\- \*\*Bob\*\*:

&nbsp; - Generates an RSA key pair

&nbsp; - Files: `public.pem`, `private.pem`

\- \*\*Alice\*\*:

&nbsp; - Creates the secret message file  

&nbsp; - File: `alice\_message.txt`



\- \*\*Encrypted and decrypted files\*\*:

&nbsp; - `encrypted\_file.bin` – file encrypted with AES-256

&nbsp; - `aes\_key\_encrypted.bin` – AES key encrypted with Bob’s RSA public key

&nbsp; - `decrypted\_message.txt` – file decrypted by Bob at the end



---



\## 3. Encryption Flow (Step by Step)



\### Step 1 – Bob generates RSA keys



1\. Bob runs the Python script.

2\. The script creates an RSA key pair (2048 bits).

3\. The keys are saved as:

&nbsp;  - `private.pem` – Bob’s private key (kept secret)

&nbsp;  - `public.pem` – Bob’s public key (shared with Alice)



This means anyone can encrypt data for Bob using `public.pem`, but only Bob can decrypt it using `private.pem`.



---



\### Step 2 – Alice creates the plaintext file



1\. Alice prepares `alice\_message.txt` with the secret message she wants to send to Bob.

2\. The script reads `alice\_message.txt` as bytes.

3\. The script also computes the \*\*SHA-256 hash\*\* of this original file.  

&nbsp;  This hash is used later to check integrity.



---



\### Step 3 – Alice generates AES-256 key and IV



1\. The script generates a random \*\*32-byte AES key\*\* (256 bits).

2\. It also generates a random \*\*16-byte IV\*\* (initialization vector) for AES in CBC mode.

3\. This key and IV are used only for this encryption session.



---



\### Step 4 – Alice encrypts the file with AES-256



1\. The content of `alice\_message.txt` is padded using PKCS7.

2\. The script encrypts the padded data using \*\*AES-256 in CBC mode\*\* with the random key and IV.

3\. The script writes one file:

&nbsp;  - `encrypted\_file.bin`  

&nbsp;    - First 16 bytes: IV  

&nbsp;    - Remaining bytes: AES ciphertext



Now Alice has the file in encrypted form. Without the AES key and correct IV, it is not readable.



---



\### Step 5 – Alice encrypts AES key with Bob’s RSA public key



1\. Alice uses `public.pem` (Bob’s public key).

2\. The AES key is encrypted using \*\*RSA with OAEP padding and SHA-256\*\*.

3\. The encrypted AES key is stored in:

&nbsp;  - `aes\_key\_encrypted.bin`



At this point Alice can send two things to Bob:



\- `encrypted\_file.bin`  

\- `aes\_key\_encrypted.bin`



The AES key is never sent in clear text.



---



\### Step 6 – Bob decrypts the AES key



1\. Bob uses `private.pem` (his RSA private key) to decrypt `aes\_key\_encrypted.bin`.

2\. The script runs RSA decryption with OAEP + SHA-256.

3\. Bob now has the original AES-256 key that Alice used.



---



\### Step 7 – Bob decrypts the file with AES-256



1\. Bob reads `encrypted\_file.bin`.

2\. The first 16 bytes are taken as the IV, the rest as the ciphertext.

3\. Using the decrypted AES key and the IV, Bob decrypts the ciphertext.

4\. The script removes PKCS7 padding and writes the result to:

&nbsp;  - `decrypted\_message.txt`



`decrypted\_message.txt` should now contain the same text as `alice\_message.txt`.



---



\### Step 8 – Integrity check with SHA-256



1\. The script computes the \*\*SHA-256 hash\*\* of `decrypted\_message.txt`.

2\. It compares this hash with the original hash from `alice\_message.txt`.

3\. If the two hashes are the same, the file has \*\*not been changed\*\* during transfer or decryption.



This gives \*\*confidentiality\*\* (because of AES + RSA) and \*\*integrity\*\* (because of SHA-256 hash comparison).



---



\## 4. AES vs RSA – Speed, Use Case, and Security



\### 4.1 Speed



\- \*\*AES-256\*\*:

&nbsp; - Very fast for large data (files, streams, many messages).

&nbsp; - Designed as a symmetric block cipher, optimized for performance.

\- \*\*RSA\*\*:

&nbsp; - Much slower, especially on big data.

&nbsp; - Not practical to encrypt large files directly with RSA.



Because of this, we only use RSA for \*\*small items\*\* like keys, not whole files.



---



\### 4.2 Use Case



\- \*\*AES-256\*\*:

&nbsp; - Used for \*\*bulk data encryption\*\*.

&nbsp; - Good for encrypting files, disks, VPN traffic, and messages.

&nbsp; - Both sides need the same secret key.



\- \*\*RSA\*\*:

&nbsp; - Used for \*\*key exchange\*\* and \*\*digital signatures\*\*.

&nbsp; - Good when two parties do not share a key yet.

&nbsp; - Public key can be shared openly, private key stays secret.



Our lab combines both: RSA protects the AES key, and AES protects the actual file.



---



\### 4.3 Security



\- \*\*AES-256\*\*:

&nbsp; - Considered very strong with a 256-bit key.

&nbsp; - No practical attacks when used correctly with random keys and IVs.

&nbsp; - Security depends on keeping the key secret.



\- \*\*RSA (2048 bits)\*\*:

&nbsp; - Also secure today when using enough key length and modern padding (like OAEP).

&nbsp; - Security is based on the difficulty of factoring large numbers.

&nbsp; - Private key must be protected; if it is stolen, attacker can decrypt data.



In practice, modern secure systems (like TLS, VPNs, and messaging apps) often use the same hybrid idea:  

\*\*Asymmetric cryptography (RSA/ECC) for key exchange + symmetric cryptography (AES) for data\*\*.



---



\## 5. Short Reflection



This task helped me understand how real secure file transfer can work in practice.  

I saw that:



\- AES is used to protect the file because it is fast and strong.

\- RSA is used to protect the AES key so that only Bob can read it.

\- SHA-256 hashing makes sure the decrypted file is exactly the same as the original one.



By checking that `decrypted\_message.txt` and `alice\_message.txt` had the same hash, I could see that the protocol was correct and that both confidentiality and integrity were achieved.




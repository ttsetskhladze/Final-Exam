\# Task 1 – Encrypted Messaging App Prototype (RSA + AES-256)



\## Goal



This mini app shows how two users (User A and User B) can send an encrypted message using a mix of \*\*RSA\*\* and \*\*AES-256\*\*.  

RSA is used for key exchange, and AES-256 is used for fast data encryption.



---



\## Roles



\- \*\*User A\*\*: Receiver  

Generates RSA key pair and keeps the private key secret.

\- \*\*User B\*\*: Sender  

 Encrypts the message with AES-256 and encrypts the AES key with RSA.



---



\## Step 1 – User A generates RSA key pair



1\. User A runs the script.

2\. The script calls `generate\_rsa\_key\_pair()` and creates:



- A 2048-bit RSA private key  

- The matching RSA public key



3\. The keys are saved to files:



 - `rsa\_private\_key.pem`  

 - `rsa\_public\_key.pem`



4\. User A keeps \*\*rsa\_private\_key.pem\*\* secret and shares \*\*rsa\_public\_key.pem\*\* with User B.



---



\## Step 2 – User B prepares the message



1\. User B writes the secret message in `message.txt`.

2\. The script reads `message.txt` and converts the text to bytes (`UTF-8`).



message.txt content:



```text

This is Taks1 file.


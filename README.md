# RSA-Encryption
 Software allowing to cipher or decipher files using RSA and AES encryption

The setup.py file is made to create a .exe version of the program, using Cx_freeze python module.

# What happens behind?
When you encrypt a file it generates a random AES key, and uses it to cipher that file.
Then, the new binary file created is composed of 4 parts:
- AES session key (RSA encrypted)
- AES nonce (RSA encrypted)
- AES tag (RSA encrypted)
- ciphered content (AES encrypted)

Therefore, when you want to decipher the file, it must be decomposed into those 4 parts, to be able to get the original file.

The algorithm and syntax used from the Crypto module (pycryptodomex) are:
- RSA => PKCS1_OAEP
- AES => EAX_MODE
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import base64
from Crypto.Random import get_random_bytes

# pip install pycryptodomex


def base_to_str(byte):
    byte = base64.b64encode(byte)
    return byte.decode('utf-8')


def str_to_base(str):
    str = str.encode("utf-8")
    return base64.b64decode(str)


def encrypt_RSA(pub_key, data):
    encryptor = PKCS1_OAEP.new(RSA.import_key(pub_key).public_key())
    ciphered_text = encryptor.encrypt(data.encode('utf-8'))
    return base_to_str(ciphered_text)


def decrypt_RSA(priv_key, data):
    data = str_to_base(data)
    decryptor = PKCS1_OAEP.new(RSA.import_key(priv_key))
    deciphered_text = decryptor.decrypt(data)

    return deciphered_text.decode("utf8")


def encrypt_AES_RSA(key_str, data):
    try:
        data = str_to_base(data)
    except:
        pass

    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    key = PKCS1_OAEP.new(RSA.import_key(key_str).public_key())
    enc_session_key = key.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return (enc_session_key, cipher_aes.nonce, tag, ciphertext)


def decrypt_AES_RSA(key_str, enc_data):
    key = RSA.import_key(key_str)

    params = []
    i = 0
    for n in (key.size_in_bytes(), 16, 16, len(enc_data)):
        params.append(enc_data[i:i+n])
        i += n
    enc_session_key, nonce, tag, ciphertext = params

    # Decrypt the session key with the private RSA key
    key = PKCS1_OAEP.new(key)
    try:
        session_key = key.decrypt(enc_session_key)
    except TypeError:
        print("The RSA key is not a private key!")
        return -1

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    try:
        return data.decode("utf-8")
    except:
        return data.decode("latin1")


def generate_RSA_key(bits=2048):
    key_pair = RSA.generate(bits)
    return key_pair.export_key().decode("utf-8"), key_pair.public_key().export_key().decode("utf-8")


def generate_RSA_public_key(key_str):
    return RSA.import_key(key_str).public_key().export_key().decode("utf-8")


def is_private(key_str):
    result = True

    try:
        pub_key = RSA.import_key(
            key_str).public_key().export_key().decode("utf-8")
        test_message = "test"
        test_enc = encrypt_RSA(pub_key, test_message)
        result = decrypt_RSA(key_str, test_enc) == test_message
    except:
        result = False

    return result


def is_public(key_str):
    result = True

    try:
        pub_key = RSA.import_key(
            key_str).public_key().export_key().decode("utf-8")
        test_message = "test"
        encrypt_RSA(pub_key, test_message)
    except:
        result = False

    return result


"""
priv, pub = generate_RSA_key()

file_out = open("file.txt", "wb")
for x in encrypt_AES_RSA(priv, "test"):
    file_out.write(x)
file_out.close()

file_in = open("file.txt", "rb")
dec = decrypt_AES_RSA(priv, file_in.read())
file_in.close()
"""

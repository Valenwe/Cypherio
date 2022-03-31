import PySimpleGUI as sg
import subprocess

# pip install pycryptodomex

from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import os
import sys


def generate_key(key_name):
    key = RSA.generate(4096)
    f = open("output/keys/" + key_name + ".pem", "wb")
    f.write(key.export_key("PEM"))
    f.close()


def generate_public_key(key_name):
    try:
        private_key = RSA.import_key(open(key_name).read())
    except IOError:
        return None

    f = open("output/keys/" + key_name.split("/")
             [-1].replace(".pem", "") + "_public.pem", "wb")
    f.write(private_key.public_key().export_key("PEM"))
    f.close()

    return key_name


def get_file_name(file_name_ext):
    i = len(file_name_ext) - 1
    while (i > 0):
        if file_name_ext[i] == ".":
            break
        i -= 1

    file_name = ""
    for I in range(0, i):
        file_name += file_name_ext[I]

    return file_name


def confirm_file_exists(file_path):
    response = True
    if os.path.isfile(file_path):
        filename = os.path.basename(file_path)
        layout = [
            [sg.Text("File "" + filename + "" already exists")],
            [sg.Text("Do you want to overwrite it?")],
            [sg.Button("Continue", enable_events=True),
             sg.Button("Cancel", enable_events=True)]
        ]

        window = sg.Window("Overwrite?", layout)

        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Cancel"):
                response = False
                break
            elif event == "Continue":
                break

        window.close()

    return response


def check_key_validation(key_name, public=True):
    response = True
    try:
        key = RSA.import_key(
            open(key_name).read())
        rsa_object = PKCS1_OAEP.new(key)
    except IOError:
        print("Error reading the RSA key!")
        sg.popup(
            "Error", "Error reading the RSA key!")
        return False

    if not public:
        try:
            if not rsa_object.can_decrypt():
                response = False
        except:
            response = False

    elif public:
        try:
            if not rsa_object.can_encrypt():
                response = False
        except:
            response = False

    if not public and not response:
        sg.popup(
            "Error", "You have to select a private key to decrypt files!")
        print("The RSA key is not a private key!")
    elif public and not response:
        sg.popup(
            "Error", "You have to select a public or private key to encrypt files!")
        print("The RSA key is not a public or private key!")

    return response


def encrypt(path, key_name, data_file_name, path_out):
    try:
        # "rb" lit le fichier en .bytes, nécessaire pour conversion
        data_file = open(path + "/" + data_file_name, "rb")
        data = data_file.read()
        data_file.close()

    except IOError:
        print("Error reading the data file!")
        return None

    # on retire l"extension
    bin_file_name = get_file_name(data_file_name)
    path_file_out = path_out + "/" + bin_file_name + ".bin"
    file_out = open(path_file_out, "wb")

    try:
        recipient_key = RSA.import_key(
            open(key_name).read())
    except IOError:
        return None

    if not confirm_file_exists(path_file_out):
        return None

    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [file_out.write(x)
     for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()

    return bin_file_name


def decrypt(path, key_name, bin_file_name, path_out):
    try:
        file_in = open(path + "/" + bin_file_name + ".bin", "rb")

        try:
            private_key = RSA.import_key(
                open(key_name).read())
        except IOError:
            print("Error reading the RSA key!")
            return None

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x)
             for x in (private_key.size_in_bytes(), 16, 16, -1)]

        file_in.close()

    except IOError:
        print("Error reading the binary file!")
        return None

    decrypted_file_path = path_out + "/" + bin_file_name + "_decrypted.bin"
    if not confirm_file_exists(decrypted_file_path):
        return None

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    try:
        session_key = cipher_rsa.decrypt(enc_session_key)
    except TypeError:
        print("The RSA key is not a private key!")
        return -1

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # print(data.decode("utf-8"))
    file = open(decrypted_file_path, "wb")
    file.write(data)
    file.close()

    return bin_file_name


def check_name_presence(name, folder):
    path = os.getcwd() + "\\output\\" + folder + "\\" + name
    return os.path.isfile(path)


def result_window(name, header, content, folder):
    layout = [
        [sg.Text(header)],
        [sg.Text(content)],
        [sg.Button("Continue", enable_events=True),
         sg.Button("View folder", enable_events=True)]
    ]

    window = sg.Window(name, layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Continue"):
            break
        elif event == "View folder":
            subprocess.Popen(r"explorer '%s'" % folder)

    window.close()


def private_key_generation():

    layout = [
        [sg.Text("Please enter the private key name: "),
         sg.Input(key="_NAME_")],
        [sg.Button("Generate", enable_events=True),
         sg.Button("Cancel", enable_events=True)]
    ]

    window = sg.Window("Private key generation", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Cancel"):
            break
        elif event == "Generate":
            if values["_NAME_"] == "":
                sg.popup("Enter a name for the key!")
            elif check_name_presence(values["_NAME_"] + ".pem", "keys"):
                sg.popup("There is already a file with that name!")
            else:
                generate_key(values["_NAME_"])
                sg.popup("Successfully generated at " + os.getcwd() +
                         "\output\keys\\" + values["_NAME_"] + ".pem")
                break

    window.close()


def public_key_generation():

    layout = [
        [sg.Text("Private key: "), sg.Input(key="_KEY_", disabled=True),
         sg.FileBrowse(file_types=(("Private key", "*.pem"),))],
        [sg.Button("Generate", enable_events=True),
         sg.Button("Cancel", enable_events=True)]
    ]

    window = sg.Window("Public key generation", layout)

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Cancel"):
            break
        elif event == "Generate":
            if values["_KEY_"] == "":
                sg.popup("You need to select a private key!")
            elif check_name_presence(values["_KEY_"] + "_public.pem", "keys"):
                sg.popup("There is already a key named " +
                         values["_KEY_"].split("/")[-1] + "_public.pem")
            else:
                output = generate_public_key(
                    values["_KEY_"])
                if output != None:
                    sg.popup("Successfully generated at " + os.getcwd() + "\output\keys\\" +
                             values["_KEY_"].split("/")[-1].replace(".pem", "") + "_public.pem")
                else:
                    sg.popup("Error reading the RSA key!")
                break

    window.close()


def guide_window():
    layout = [
        [sg.Text("How to use this program\nThis program is using standard RSA encryption, with asymmetrical keys\n\nA private key allows you to cypher and decypher any file, a public key can only cypher files\nYou can only decypher .bin files")],
        [sg.OK()]
    ]

    window = sg.Window("Guide", layout)
    event, values = window.read()
    window.close()


if getattr(sys, "frozen", False):
    application_path = os.path.dirname(sys.executable)
elif __file__:
    application_path = os.path.dirname(__file__)

os.chdir(application_path)

if not os.path.isdir(os.getcwd() + "/output"):
    os.mkdir(os.getcwd() + "/output")

if not os.path.isdir(os.getcwd() + "/output/encrypted"):
    os.mkdir(os.getcwd() + "/output/encrypted")

if not os.path.isdir(os.getcwd() + "/output/decrypted"):
    os.mkdir(os.getcwd() + "/output/decrypted")

if not os.path.isdir(os.getcwd() + "/output/keys"):
    os.mkdir(os.getcwd() + "/output/keys")

sg.theme("LightBrown13")
target_files = []
menu_def = [["&Key generation", ["&Generate private key", "&Generate public key", "&Exit"]],
            ["&Help", ["&Guide", "&About"]], ]
layout = [
    [sg.Menu(menu_def, tearoff=False, pad=(200, 1))],
    [sg.Text("Key"), sg.Input(key="_KEY_", size=(100, 5), disabled=True),
     sg.FileBrowse("Add", file_types=(("Key", "*.pem"),), tooltip="Select a key")],
    [sg.Listbox(values=target_files, enable_events=True, size=(
        100, 20), select_mode=sg.LISTBOX_SELECT_MODE_EXTENDED, key="_FILES_")],
    [sg.FilesBrowse("Add files", key="_BR_", enable_events=True, file_types=(
        ("All files", "*.*"), ("Binary files", "*.bin"),), tooltip="Add files to selection")],
    [sg.Button("Remove", enable_events=True, tooltip="Remove file selection")],
    [sg.Button("Encrypt", enable_events=True, tooltip="Encrypt file selection"),
     sg.Button("Decrypt", enable_events=True, tooltip="Decrypt file selection")]
]

window = sg.Window("Cypherio", layout)

while True:
    event, values = window.read()
    # print(event, values)

    if event in (sg.WIN_CLOSED, "Exit"):
        break

    elif event == "_BR_":
        target_files += values["_BR_"].split(";")
        window["_FILES_"].update(target_files)

    elif event == "Remove":
        temp = []
        for file in target_files:
            selected = False

            for element in values["_FILES_"]:
                if file == element:
                    selected = True
                    break

            if not selected:
                temp.append(file)

        target_files = temp
        window["_FILES_"].update(target_files)

    elif event == "Generate private key":
        private_key_generation()

    elif event == "Generate public key":
        public_key_generation()

    elif event == "About":
        sg.popup("About", "Version 1.1",
                 "Cypherio created by Valenwe", grab_anywhere=True)

    elif event == "Guide":
        guide_window()

    elif event == "Encrypt":
        if len(target_files) == 0:
            sg.popup("You have to add files to encrypt!")
        elif values["_KEY_"] == "":
            sg.popup("You have to select a public or private key!")
        else:
            if check_key_validation(values["_KEY_"]):
                results = []
                for element in target_files:
                    if encrypt(element.replace(
                            "/" + element.split("/")[-1], ""), values["_KEY_"], element.split("/")[-1], "output/encrypted") == None:
                        results.append("failed")
                    else:
                        results.append("success")

                popup = ""
                for i in range(0, len(results)):
                    popup += target_files[i].split("/")[-1] + \
                        " => " + target_files[i].split("/")[-1].replace(
                            "." + target_files[i].split(".")[-1], "") + ".bin ~~ " + results[i] + "\n"
                result_window("Encryption", "File encryption report",
                              popup, os.getcwd() + "\output\encrypted")
                target_files = []
                window["_FILES_"].update(target_files)

    elif event == "Decrypt":
        if len(target_files) == 0:
            sg.popup("You have to add files to decrypt!")
        elif values["_KEY_"] == "":
            sg.popup("You have to select a private key!")
        else:
            bin = True
            for element in target_files:
                if not element.endswith(".bin"):
                    sg.popup("You have to select .bin files only!")
                    bin = False

            if bin and check_key_validation(values["_KEY_"], public=False):
                results = []
                for element in target_files:
                    if decrypt(element.replace("/" + element.split("/")[-1], ""), values["_KEY_"], element.split(
                            "/")[-1].replace(".bin", ""), "output/decrypted") == None:
                        results.append("failed")
                    else:
                        results.append("success")

                popup = ""
                for i in range(0, len(results)):
                    popup += target_files[i].split("/")[-1] + \
                        " => " + target_files[i].split("/")[-1].replace(
                            ".bin", "") + "_decrypted.bin ~~ " + results[i] + "\n"

                result_window("Decryption", "File decryption report",
                              popup, os.getcwd() + "\output\decrypted")

                target_files = []
                window["_FILES_"].update(target_files)

window.close()

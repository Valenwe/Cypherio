import PySimpleGUI as sg
import subprocess
import os
import sys
import logging

import crypto

# Characters after the name of the encrypted file.
encrypted_suffix = "_encrypted"

def generate_key(key_name, bits=2048):
    priv, _ = crypto.generate_RSA_key(bits)
    with open("output/keys/" + key_name + ".pem", "w") as f:
        f.write(priv)


def generate_public_key(key_name):
    try:
        priv_str = open(key_name).read()
        pub_str = crypto.generate_RSA_public_key(priv_str)
    except:
        return None

    with open("output/keys/" + key_name.split("/")
             [-1].replace(".pem", "") + "_public.pem", "w") as f:
        f.write(pub_str)

    return key_name


def confirm_file_exists(file_path):
    response = True
    if os.path.isfile(file_path):
        filename = os.path.basename(file_path)
        layout = [
            [sg.Text("File " + filename + " already exists")],
            [sg.Text("Do you want to overwrite it?")],
            [sg.Button("Continue", enable_events=True),
             sg.Button("Cancel", enable_events=True)]
        ]

        window = sg.Window("Overwrite?", layout, icon="favicon.ico")

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
    key_str = open(key_name).read()

    if not public:
        response = crypto.is_private(key_str)
    else:
        response = crypto.is_public(key_str)

    if not response:
        if not public:
            sg.popup(
                "Error", "You have to select a private key to decrypt files!")
            logging.error("The RSA key is not a private key!")
        else:
            sg.popup(
                "Error", "You have to select a public or private key to encrypt files!")
            logging.error("The RSA key is not a public or private key!")

    return response


def encrypt(filepath, key_name, path_out):
    try:
        # "rb" lit le fichier en .bytes, nécessaire pour conversion
        data_file = open(filepath, "rb")
        data = data_file.read()
        data_file.close()

    except IOError:
        logging.error("Error reading the data file!")
        return None

    try:
        key_str = open(key_name).read()
    except IOError:
        logging.error("Error reading the RSA key!")
        return None

    basename = os.path.splitext(os.path.basename(filepath))
    bin_file_name = basename[0] + encrypted_suffix + basename[1]
    path_file_out = path_out + "/" + bin_file_name

    if not confirm_file_exists(path_file_out):
        return None

    with open(path_file_out, "wb") as file_out:
        [file_out.write(x)
        for x in crypto.encrypt_AES_RSA(key_str, data)]

    return bin_file_name


def decrypt(filepath, key_name, path_out):
    try:
        key_str = open(key_name).read()
    except IOError:
        logging.error("Error reading the RSA key!")
        return None

    try:
        file = open(filepath, "rb")
        enc_data = file.read()
        file.close()
    except IOError:
        logging.error("Error reading the binary file!")
        return None

    basename = os.path.splitext(os.path.basename(filepath))
    bin_file_name = basename[0].split(encrypted_suffix)[0] + basename[1]
    decrypted_file_path = path_out + "/" + bin_file_name

    if not confirm_file_exists(decrypted_file_path):
        return None

    data = crypto.decrypt_AES_RSA(key_str, enc_data)

    if data == None:
        logging.error("Failed to decrypt file.")
        return None

    with open(decrypted_file_path, "wb") as file:
        file.write(data)

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

    window = sg.Window(name, layout, icon="favicon.ico")

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Continue"):
            break
        elif event == "View folder":
            subprocess.call('start %windir%/explorer.exe "' +
                            r"%s" % folder + '"', shell=True)

    window.close()


def private_key_generation():

    layout = [
        [sg.Text("Please enter the private key name: "),
         sg.Input(key="_NAME_")],
        [sg.Text("Bit size: "), sg.OptionMenu(
            values=["2048", "4096"], default_value="2048", key='_BITS_')],
        [sg.Button("Generate", enable_events=True),
         sg.Button("Cancel", enable_events=True)]
    ]

    window = sg.Window("Private key generation", layout, icon="favicon.ico")

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
                generate_key(values["_NAME_"], int(values["_BITS_"]))
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

    window = sg.Window("Public key generation", layout, icon="favicon.ico")

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
        [sg.Text("How to use this program\nThis program is using standard RSA encryption, with asymmetrical keys\n\nA private key allows you to cypher and decypher any file, a public key can only cypher files\nYou can only decypher binary files")],
        [sg.OK()]
    ]

    window = sg.Window("Guide", layout, icon="favicon.ico")
    window.read()
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
     sg.FileBrowse("Select", file_types=(("Key", "*.pem"),), tooltip="Select a key")],
    [sg.Listbox(values=target_files, enable_events=True, size=(
        100, 20), select_mode=sg.LISTBOX_SELECT_MODE_EXTENDED, key="_FILES_")],
    [sg.FilesBrowse("Add files", key="_BR_", enable_events=True, file_types=(
        ("All files", "*.*"),), tooltip="Add files to selection")],
    [sg.Button("Remove", enable_events=True, tooltip="Remove file selection")],
    [sg.Button("Encrypt", enable_events=True, tooltip="Encrypt file selection"),
     sg.Button("Decrypt", enable_events=True, tooltip="Decrypt file selection")]
]

window = sg.Window("Cypherio", layout, icon="favicon.ico")

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
                results = {}
                popup = ""
                for element in target_files:
                    encrypted_filename = encrypt(element, values["_KEY_"], "output/encrypted")
                    results[encrypted_filename] = "failed" if encrypted_filename == None else "success"

                    popup += os.path.basename(element) + \
                        " => " + encrypted_filename + \
                        " ~~ " + results[encrypted_filename] + "\n"

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

            if check_key_validation(values["_KEY_"], public=False):
                results = {}
                popup = ""
                for element in target_files:
                    decrypted_filename = decrypt(element, values["_KEY_"], "output/decrypted")
                    results[decrypted_filename] = "failed" if decrypted_filename == None else "success"

                    popup += os.path.basename(element) + \
                        " => " + decrypted_filename + \
                        " ~~ " + results[decrypted_filename] + "\n"

                result_window("Decryption", "File decryption report",
                              popup, os.getcwd() + "\output\decrypted")

                target_files = []
                window["_FILES_"].update(target_files)

window.close()

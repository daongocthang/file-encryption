from cryptography.fernet import Fernet
import os


def write_key(filename):
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()
    with open(filename, "wb") as key_file:
        key_file.write(key)


def load_key(filename):
    """
    Loads the key from a file
    """
    return open(filename, "rb").read()


def encrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it encrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read all file data
        file_data = file.read()
    # encrypt data
    encrypted_data = f.encrypt(file_data)
    # write the encrypted file
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt(filename, key):
    """
    Given a filename (str) and key (bytes), it decrypts the file and write it
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = f.decrypt(encrypted_data)
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple File Encryptor Script")
    parser.add_argument("file", help="File to encrypt/decrypt")
    parser.add_argument("-g", "--generate-key", dest="generate_key", action="store_true",
                        help="Whether to generate a new key or use existing")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Whether to encrypt the file, only -e or -d can be specified.")
    parser.add_argument("-d", "--decrypt", action="store_true",
                        help="Whether to decrypt the file, only -e or -d can be specified.")

    args = parser.parse_args()
    file = args.file
    key_file = os.path.join(os.path.dirname(file), '.key')
    generate_key = args.generate_key

    has_key = os.path.isfile(key_file)
    if generate_key:
        if not has_key:
            write_key(key_file)
        else:
            confirm = input("The key file is available. Do you want to replace it?(Y/N) ")
            if confirm == "Y":
                write_key(key_file)
    try:
        # load the key
        assert os.path.isfile(key_file), "The key file not found at {}".format(os.path.dirname(file))
        key = load_key(key_file)

        encrypt_ = args.encrypt
        decrypt_ = args.decrypt

        if encrypt_ and decrypt_:
            raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")
        elif encrypt_:
            encrypt(file, key)
            print("Done.")
        elif decrypt_:
            decrypt(file, key)
            print("Done.")
        else:
            raise TypeError("Please specify whether you want to encrypt the file or decrypt it.")
    except Exception as e:
        print(e)

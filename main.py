import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

fileNameForEncryption = ""
fileNameForDecryption = ""
filePathForEncryption = ""
filePathForDecryption = ""

privateKeyFilePathForDecryption = ""
publicKeyFilePathForEncryption = ""

def select_file_for_encryption():
    global fileNameForEncryption, filePathForEncryption, publicKeyFilePathForEncryption
    
    # Select file for encryption
    filePathForEncryption = filedialog.askopenfilename(title="Select file for encryption", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    if filePathForEncryption:
        fileNameForEncryption = filePathForEncryption.split("/")[-1]
    generate_key_pair()
    encrypt()

def select_file_for_decryption():
    global fileNameForDecryption, filePathForDecryption, privateKeyFilePathForDecryption

    # Select file for decryption
    filePathForDecryption = filedialog.askopenfilename(title="Select file for decryption", filetypes=(("Text Files", "*.txt"), ("All Files", "*.*")))
    if filePathForDecryption:
        fileNameForDecryption = filePathForDecryption.split("/")[-1]

    # Select private key file for decryption
    privateKeyFilePathForDecryption = filedialog.askopenfilename(title="Select private key file")
    
    decrypt()

def generate_key_pair():
    global fileNameForEncryption, publicKeyFilePathForEncryption
    
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save the private key into file
    with open(fileNameForEncryption + "_private_key.pem", 'wb') as file:
        file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save the public key into file
    public_key = private_key.public_key()
    with open(fileNameForEncryption + "_public_key.pem", 'wb') as file:
        file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    publicKeyFilePathForEncryption = fileNameForEncryption + "_public_key.pem"

def encrypt():
    global fileNameForEncryption, filePathForEncryption, publicKeyFilePathForEncryption
    key = Fernet.generate_key()

    # Read data from file
    with open(filePathForEncryption, 'rb') as file:
        data = file.read()
    
    # Encrypt data with symmetric key
    f_symmetric = Fernet(key)
    encrypted_data_symmetric = f_symmetric.encrypt(data)

    # Encrypt symmetric key with public key
    with open(publicKeyFilePathForEncryption, 'rb') as file:
        public_key = serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Save the encrypted data and encrypted symmetric key into files
    with open("enc_" + fileNameForEncryption, 'wb') as file:
        file.write(encrypted_data_symmetric)
    with open("enc_" + fileNameForEncryption + "_key", 'wb') as file:
        file.write(encrypted_key)

def decrypt():
    global fileNameForDecryption, filePathForDecryption, privateKeyFilePathForDecryption

    # Read private key from file
    with open(privateKeyFilePathForDecryption, 'rb') as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=None,
            backend=default_backend()
        )

    # Read encrypted data and encrypted symmetric key from files
    with open(filePathForDecryption, 'rb') as file:
        encrypted_data_symmetric = file.read()
    with open(filePathForDecryption + "_key", 'rb') as file:
        encrypted_key = file.read()

    # Decrypt symmetric key with private key
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt data with symmetric key
    f_symmetric = Fernet(decrypted_key)
    decrypted_data = f_symmetric.decrypt(encrypted_data_symmetric)

    # Save the decrypted data into file
    with open("dec_" + fileNameForDecryption, 'wb') as file:
        file.write(decrypted_data)


root = tk.Tk()
root.title("File Encryption Decryption")

button_encrypt = tk.Button(root, text="Select File For Encryption", command=select_file_for_encryption)
button_decrypt = tk.Button(root, text="Select File For Decryption", command=select_file_for_decryption)
button_encrypt.pack(pady=20, padx=5)
button_decrypt.pack(pady=20, padx=5)

root.mainloop()

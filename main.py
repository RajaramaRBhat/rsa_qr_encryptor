from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import qrcode
import os

def generate_keys():
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    return key, key.publickey()

def encrypt_message(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode())
    return ciphertext.hex()

def generate_qr(data, filename="encrypted_qr.png"):
    qr = qrcode.make(data)
    qr.save(filename)
    print(f"\nQR code saved as {filename}")

def decrypt_message(private_key, hex_data):
    cipher = PKCS1_OAEP.new(private_key)
    encrypted_bytes = bytes.fromhex(hex_data)
    decrypted = cipher.decrypt(encrypted_bytes)
    return decrypted.decode()

def main():
    print("RSA QR Tool")
    print("1. Encrypt message & generate QR")
    print("2. Decrypt from scanned QR hex\n")
    choice = input("Choose an option (1 or 2): ").strip()

    if choice == "1":
        msg = input("Enter the message to encrypt: ")
        key, pubkey = generate_keys()
        encrypted_hex = encrypt_message(pubkey, msg)
        generate_qr(encrypted_hex)
        print("Private key saved to 'private.pem'. Keep it safe!")

    elif choice == "2":
        if not os.path.exists("private.pem"):
            print("Private key file 'private.pem' not found.")
            return
        with open("private.pem", "rb") as f:
            priv_key = RSA.import_key(f.read())
        hex_input = input("\nPaste the encrypted hex string from scanned QR code:\n")
        try:
            original = decrypt_message(priv_key, hex_input)
            print("\nDecrypted message:", original)
        except Exception as e:
            print("\nError during decryption:", str(e))

    else:
        print("Invalid option. Exiting.")

if __name__ == "__main__":
    main()

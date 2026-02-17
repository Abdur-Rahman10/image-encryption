import os
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend

# --- Core Logic ---

def derive_key(password, salt):
    """Derives a secure 32-byte key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_image(image_path, password):
    try:
        # Read the image data
        with open(image_path, 'rb') as f:
            image_data = f.read()

        # Generate a random salt (16 bytes) and IV (16 bytes)
        salt = os.urandom(16)
        iv = os.urandom(16)

        # Derive the key
        key = derive_key(password, salt)

        # Pad the image data (PKCS7 with 128-bit block size)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(image_data) + padder.finalize()

        # Encrypt the data using AES in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save Salt + IV + Encrypted Data to a single file
        output_path = 'encrypted_' + os.path.basename(image_path) + '.bin'
        with open(output_path, 'wb') as f:
            f.write(salt + iv + encrypted_data)

        print(f"\n[Success] Image encrypted to '{output_path}'")
    
    except FileNotFoundError:
        print(f"\n[Error] The file '{image_path}' was not found.")
    except Exception as e:
        print(f"\n[Error] An error occurred: {e}")

def decrypt_image(encrypted_image_path, password):
    try:
        # Read the encrypted file
        with open(encrypted_image_path, 'rb') as f:
            salt = f.read(16)   # First 16 bytes are Salt
            iv = f.read(16)     # Next 16 bytes are IV
            encrypted_data = f.read() # The rest is the image data

        # Derive the same key using the extracted salt
        key = derive_key(password, salt)

        # Decrypt the data
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # Save the restored image
        output_path = 'decrypted_' + os.path.basename(encrypted_image_path).replace('.bin', '.jpg')
        with open(output_path, 'wb') as f:
            f.write(data)

        print(f"\n[Success] Image decrypted to '{output_path}'")

    except ValueError:
        print("\n[Error] Decryption failed. Incorrect password or corrupted file.")
    except FileNotFoundError:
        print(f"\n[Error] The file '{encrypted_image_path}' was not found.")
    except Exception as e:
        print(f"\n[Error] An error occurred: {e}")

# --- User Interface ---

def main():
    print("--- Image Encryption Tool ---")
    
    while True:
        print("\nChoose an option:")
        print("1. Encrypt an Image")
        print("2. Decrypt an Image")
        print("3. Exit")
        
        choice = input("Select (1-3): ").strip()

        if choice == '1':
            image_path = input("Enter the path to the image (e.g., photo.jpg): ").strip()
            password = getpass.getpass("Set a password: ").strip()
            encrypt_image(image_path, password)
        
        elif choice == '2':
            encrypted_path = input("Enter path to encrypted file (e.g., encrypted_image.bin): ").strip()
            password = getpass.getpass("Enter the password: ").strip()
            decrypt_image(encrypted_path, password)
        
        elif choice == '3':
            print("Exiting program. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
# 🔒 Secure Image Encryptor (AES-256)

A Python-based cybersecurity tool that encrypts and decrypts image files using AES-256 (Advanced Encryption Standard). It utilizes PBKDF2 for secure key derivation, ensuring that your private images remain inaccessible without the correct password.

## 🚀 Key Features

* **AES-256 Encryption:** Uses the industry-standard algorithm in CBC (Cipher Block Chaining) mode.
* **Secure Key Derivation:** Implements PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA256 and a random salt to prevent rainbow table attacks.
* **Data Integrity:** Applies PKCS7 padding to ensure data blocks are perfectly aligned for encryption.
* **User-Friendly CLI:** Simple command-line interface for easy encryption and decryption.

## 🛠️ Technologies Used

* **Language:** Python 3.x
* **Library:** `cryptography`
* **Modules:** `os`, `getpass`, `base64`

## 📦 Installation

**1. Clone the Repository:**
```bash
git clone (https://github.com/Abdur-Rahman10/image-encryption.git)
cd image-encryption
```

2. Install Dependencies:
This tool requires the cryptography library.
```Bash
pip install cryptography
```

📖 Usage
Run the script using Python:
```Bash
python image_encryptor.py
```

1. Encrypt an Image
Select option 1.

Enter the full path to your image (e.g., my_photo.jpg).

Set a strong password.

Result: A new file named encrypted_my_photo.bin will be created. This file is unreadable without the key.

2. Decrypt an Image
Select option 2.

Enter the path to the encrypted file (e.g., encrypted_my_photo.bin).

Enter the original password.

Result: The original image is restored as decrypted_my_photo.jpg.

⚙️ How It Works (Technical Details)
Salt Generation: A random 16-byte salt is generated for every new encryption to ensure that the same password produces a different key every time.

Key Derivation: The tool uses PBKDF2HMAC with 100,000 iterations to derive a 32-byte key from your password.

Encryption: The image binary is padded (PKCS7) and encrypted using AES-CBC. The Salt and IV (Initialization Vector) are prepended to the file so they can be used for decryption.

⚠️ Disclaimer
Do not lose your password. There is no "forgot password" feature. If you lose the password, the data is permanently lost.

Do not modify the encrypted .bin file. Altering even one byte can corrupt the entire image or make decryption impossible.

👤 Author
Abdur Rahman

GitHub: @Abdur-Rahman10

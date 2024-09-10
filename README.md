# ZEPHYRN SECURITIES 

## File Encryptor & Decryptor

This Python application provides an intuitive user interface for file encryption and decryption using the AES-256 algorithm. It allows users to encrypt files of any type (e.g., PDF, images, videos, audio, documents) and later decrypt them using the same password. The app supports drag-and-drop functionality, ensures security with AES-256 encryption, and offers a clean and user-friendly experience.

### Features

- File Encryption: Securely encrypt any file using AES-256 encryption.
- File Decryption: Decrypt previously encrypted files.
- User-Friendly Interface: Simple drag-and-drop feature and easy file selection.
- Password Protection: Use a password to ensure only authorized users can decrypt files.
- Progress Indicator: Shows a loading bar while files are being processed.
- Error Handling: User is notified of success or failure of the encryption/decryption process.
- Cross-Platform: Works on both Windows and macOS with Python 3.

### Technologies Used

- Python 3
- Tkinter (for GUI)
- PyCryptodome (for AES-256 encryption)
- Threading (for handling GUI responsiveness)

### Installation

1. Clone the repository to your local machine:

         git clone https://github.com/harsh11x/zephyrn.git

2. Navigate to the project directory:

         cd File-Encryptor-Decryptor

3. Install the required dependencies:

         pip3 install pycryptodome

         pip3 install tk

5. Run the application

         python3 encryptor.py   (To run the encryption tool)

         python3 decryptor.py   (To run the decryption tool)

### Usage

1. File Encryption

   - Open the encryption application

           python3 encryptor.py

   - Select the file you want to encrypt by clicking the "Choose File" button.

   - Enter a password when prompted to generate an AES-256 key.

   - The file will be encrypted and saved with an .enc extension.

   - Upon completion, a success message will appear.

 ### When the appication asks for password enter star: * as a password 


2. File Decryption

   - Open the decryption application
  
           python3 descryption.py

   - Select the .enc file that you want to decrypt.

   - Enter the same password used during encryption.

   - The file will be decrypted and saved without the .enc extension.

   - A success message will confirm the operation.



## Code Breakdown

### Encryption Workflow

- File Selection: The user selects the file to encrypt the filedialog.askopenfilename() function.
- Password Input: A password is entered through simpledialog.askstring(). This password is hashed using SHA-256 to generate a 256-bit key.
- AES Encryption: The file is encrypted using AES-256 in CBC mode. An IV (initialization vector) is generated randomly and stored with the file.
- Progress Bar: A progress bar is displayed during the encryption process to provide visual feedback.
- Success/Error Handling: Once the file is successfully encrypted, a message box confirms success. In case of any errors, an error message is shown.

### Decryption Workflow

- File Selection: The user selects an encrypted file (.enc).
- Password Input: The same password used for encryption is required.
- AES Decryption: The file is decrypted using the same AES-256 key and initialization vector.
- File Restoration: The decrypted file is saved with its original extension, and padding is removed.
- Progress Bar: A progress bar is displayed during the decryption process to show the status.


## Requirements

- Python 3.x
- PyCryptodome library (pip install pycryptodome)
- Tkinter (pre-installed with Python)












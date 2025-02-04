# File Encryption and Decryption Tool 🔒

## Description
The **File Encryption and Decryption Tool** is a JavaFX-based desktop application that provides secure encryption and decryption of files using **AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman)** algorithms. The application includes a **login authentication system** and a **user-friendly GUI** for selecting files and performing encryption and decryption with ease.

## Features
- **Secure Authentication**: Basic login system to restrict access.
- **AES Encryption**: Encrypts files using AES-128 for fast and efficient security.
- **RSA Encryption**: Encrypts the AES key using RSA-2048 for enhanced security.
- **User-Friendly GUI**: Simple JavaFX-based interface for easy interaction.
- **File Handling**: Allows users to select files for encryption/decryption through a file picker.
- **Success/Error Alerts**: Displays notifications for successful encryption, decryption, or errors.

## Technologies Used
- **JavaFX**: For the graphical user interface.
- **Java Cryptography API**: Provides encryption and decryption functionalities.
- **AES-128 & RSA-2048**: Ensures secure encryption and decryption processes.
- **File Handling**: Reads and writes encrypted files efficiently.

## Installation and Usage
### Prerequisites
- Java Development Kit (JDK) 8 or later
- JavaFX library (included in JDK 11+)

### Steps to Run
1. Clone the repository:
   ```sh
   git clone https://github.com/Shash2i1/File-Encryption-Decryption.git
   ```
2. Navigate to the project directory:
   ```sh
   cd File-Encryption-Decryption
   ```
3. Compile and run the Java application:
   ```sh
   javac FileEncryptionTool.java
   java FileEncryptionTool
   ```

## How It Works
1. **Login**: Enter a valid username and password to access the encryption/decryption interface.
2. **Encrypt a File**:
   - Select a file using the **file chooser**.
   - The system generates an **AES key**, encrypts the file, and stores the AES key securely using **RSA encryption**.
   - The encrypted file is saved with a `.enc` extension.
3. **Decrypt a File**:
   - Select an encrypted `.enc` file.
   - The system retrieves and decrypts the AES key using RSA.
   - The encrypted data is decrypted using AES and saved with a `.dec` extension.

## Project Structure
```
File-Encryption-Decryption/
│-- src/
│   │-- FileEncryptionTool.java  # Main application file
│   │-- encryption/              # Encryption-related functions
│   │-- ui/                      # UI components (JavaFX)
│-- README.md
│-- LICENSE
```

## Future Enhancements
- Add user authentication with hashed passwords.
- Support for larger file encryption optimization.
- Implement AES-256 for stronger security.

## Author
👤 **Shashank**  
🔗 GitHub: [Shash2i1](https://github.com/Shash2i1)



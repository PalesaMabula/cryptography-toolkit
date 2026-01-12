# 🔐 Cryptography Toolkit (Python)

A modular Python-based cryptography toolkit that demonstrates core security concepts including file hashing, data integrity verification, symmetric and asymmetric encryption, and secure password management.

This project is designed for **educational, academic, and portfolio purposes**, showcasing practical implementations of cryptographic principles used in modern cybersecurity systems.

---

## 🚀 Features

### ✅ File Hashing & Integrity Verification
- Uses **SHA-256** to generate cryptographic hashes
- Detects file tampering by comparing hash values
- Efficient chunk-based hashing for large files

### 🔒 Encryption & Decryption
- **AES-GCM (Symmetric Encryption)**
  - Secure random key & nonce generation
  - Ensures confidentiality and integrity
- **RSA (Asymmetric Encryption)**
  - Public-key encryption & private-key decryption
  - Uses OAEP padding with SHA-256

### 🔑 Secure Password Management
- Password strength analysis using **zxcvbn**
- Secure password hashing using **bcrypt**
- Password verification without storing plaintext passwords

### 🧭 Interactive Menu
- Command-line interface for easy navigation
- Modular design for scalability and maintenance


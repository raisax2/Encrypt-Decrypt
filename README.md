# Encrypt-Decrypt

A lightweight Python command-line tool that encrypts and decrypts files using AES-256-GCM encryption with PBKDF2-HMAC-SHA256 key derivation. This project demonstrates practical cybersecurity concepts like authenticated encryption, password-based key generation, and secure file formatting.

---

## Features
- AES-256-GCM encryption for strong data confidentiality and integrity  
- Password-based key derivation using PBKDF2 with salt  
- Defined file format: `MAGIC | SALT | NONCE | CIPHERTEXT+TAG`  
- Simple CLI for quick encryption and decryption  
- Lightweight, easy to set up, beginner-friendly

---

## Requirements
- Python 3.7+  
- `cryptography` library

Install dependencies with:
```bash
pip install -r requirements.txt

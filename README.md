# End-to-End Encrypted Chat Protocol (ECC Implementation)

<p align="center">
  <img src="dem" alt="ECC Chat Protocol Demo" width="800">
</p>

<p align="center">
  <b>A secure, terminal-based communication simulation using Elliptic Curve Cryptography (ECC).</b>
  <br>
  Generated with C++ • NIST P-256 • ECDH • ECDSA
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C++-00599C?style=flat-square&logo=c%2B%2B" alt="C++">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Status-Educational-orange?style=flat-square" alt="Status">
</p>

---

## 📖 Overview

This project is a custom C++ implementation of a secure cryptographic protocol designed to demonstrate the principles of **End-to-End Encryption (E2EE)**. 

Unlike standard wrappers around OpenSSL, this project manually implements the core mathematical logic for **Elliptic Curve Cryptography**, including point addition, scalar multiplication, and modular arithmetic on large integers. It simulates a secure channel establishment and message exchange between two parties (Alice and Bob).

## 🔐 Key Features & Algorithms

The protocol is built upon the following cryptographic primitives:

* **Elliptic Curve:** Standard **NIST P-256** (secp256r1) domain parameters.
* **Key Exchange (ECDH):** Elliptic Curve Diffie-Hellman for deriving a shared secret over an insecure channel.
* **Digital Signatures (ECDSA):** Elliptic Curve Digital Signature Algorithm to ensure message integrity and sender authenticity.
* **Hashing (KDF):** **SHA-256** is used as a Key Derivation Function to transform the ECDH shared secret into a symmetric key.
* **Encryption:** Symmetric **XOR Cipher** (using the derived session key) for confidentiality.
* **Big Integer Arithmetic:** Handling of 256-bit integers required for ECC operations.

## 🚀 How It Works

The simulation follows a "Sign-then-Encrypt" paradigm:

1.  **Key Generation:** Alice and Bob generate their private and public keys using the NIST P-256 curve.
2.  **Handshake:** They exchange public keys and compute the **Shared Secret** using ECDH.
3.  **Message Creation:** Alice inputs a message for Bob.
4.  **Signature:** Alice hashes the message (SHA-256) and signs the hash with her **Private Key** (ECDSA).
5.  **Encryption:** The message is encrypted using the session key derived from the Shared Secret.
6.  **Transmission:** The encrypted payload + signature are "sent" to Bob.
7.  **Decryption:** Bob decrypts the message using his copy of the Shared Secret.
8.  **Verification:** Bob verifies Alice's signature against the decrypted message hash using Alice's **Public Key**.

## 🛠️ Dependencies

This project uses header-only libraries for big integer arithmetic and hashing to keep the codebase lightweight and portable:

* **[InfInt](https://github.com/sercantutar/infint)** by Sercan Tutar - For arbitrary-precision integer arithmetic.
* **[PicoSHA2](https://github.com/okdshin/PicoSHA2)** by okdshin - For SHA-256 hashing operations.

## 💻 Compilation & Usage

Ensure you have a C++ compiler installed (e.g., G++, Clang, MSVC).

1.  Clone the repository:
    ```bash
    git clone [https://github.com/KacperMiziolek/ECC-Chat-Protocol.git](https://github.com/KacperMiziolek/ECC-Chat-Protocol.git)
    cd ECC-Chat-Protocol
    ```

2.  Compile the source code:
    ```bash
    g++ main.cpp -o secure_chat -O3
    ```

3.  Run the simulation:
    ```bash
    ./secure_chat
    # On Windows: .\secure_chat.exe
    ```


## 📄 License

This project is licensed under the **MIT License**. See the LICENSE file for details.

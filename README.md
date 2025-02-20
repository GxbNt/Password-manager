### Password Manager with Custom Ciphers
Password manager tool that encrypts/decrypts credentials using 2 block ciphers and 2 stream ciphers, all implemented from scratch. Designed to demonstrate custom cryptography workflows.

### Encryption Workflow
**Block Ciphers**

1. **SimpleSPN (Substitution-Permutation Network)**  
   A block cipher that performs encryption through a combination of substitution, permutation, and XOR operations with the key.  
   - **Rounds**: 10  
   - **Operations**:  
     - Substitutes bytes based on a lookup table.  
     - Permutes the bits within the block.  
     - XORs the resulting block with the key to produce the final ciphertext.

2. **Feistel Network**  
   A classic symmetric block cipher structure that splits the data into two halves and processes them through multiple rounds.  
   - **Rounds**: 16  
   - **Padding**: Uses PKCS#7 padding to ensure data integrity.  
   - **Operations**:  
     - Data is split into left and right halves.  
     - Each half is processed through a series of rounds, mixing and applying the key.

**Stream Ciphers**

1. **LFSR (Linear Feedback Shift Register)**  
   A lightweight stream cipher that generates a keystream by shifting bits in a register and using feedback.  
   - **Feedback bits**: Bits 0 and 2 of the register are used for feedback to generate the next keystream bit.

2. **RC4-like Cipher**  
   A stream cipher based on the RC4 algorithm, using a state array to generate pseudorandom bytes.  
   - **Operations**:  
     - The cipher generates keystream by swapping elements within the state array, producing a stream of random-looking bytes.

## Features

- 🔒 **Master Password Protection**: Securely derive keys using PBKDF2-HMAC for robust encryption.
- 🛡️ **Layered Encryption**: Utilizes 4 custom ciphers, including 2 block ciphers and 2 stream ciphers, for added security.
- 📁 **Automatic Database Handling**: Encrypted credentials are safely stored in a `passwords.json` file.
- 🔄 **Error Recovery**: Gracefully resets corrupted databases to prevent data loss.
- 💻 **CLI Interface**: Simple, menu-driven interaction for an easy-to-use command-line experience.


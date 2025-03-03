# BackupServer Project
### Overview
Welcome to the **BackupServer** project! This multi-threaded client-server application is designed to handle large files securely and efficiently.  
The project utilizes various technologies, including cryptographic libraries, SQLite3 for database management, socket programming, file handling (including binary files), threading, and checksum calculations, with a slight twist on Linux's traditional approach.  

### Key Features 
- **Client Registration**: If clients aren't registered, they must first register with the server.
- **RSA Key Pair**: The client generates an RSA key pair and sends the public key to the server.
- **Symmetric Key Exchange**: The server generates a symmetric encryption key, encrypts it with the client's RSA public key, and sends it back. The client decrypts it to establish a shared symmetric key.
- **File Transfer**: Files are sent in encrypted chunks to ensure efficient memory usage for both the client and server.
- **Checksum Verification**: After receiving a file, the server calculates a checksum (using a method inspired by Linux) and sends it to the client for validation.
- **Error Recovery**: If the checksum verification fails, the client will attempt to resend the file up to three times.
- **Directory Management**: If the client doesn't have a pre-existing directory, the server will create one for the client to store their files.
- **Reconnection**: If the client is already registered, they can reconnect to the server to send additional files. A new key is generated for each session.

### How It Works
- **Client Registration**: If the client is not registered with the server, they must complete the registration process.
- **RSA Key Pair Generation**: The client generates an RSA key pair and sends the public key to the server.
- **Symmetric Key Exchange**: The server generates a symmetric encryption key, encrypts it with the client's public RSA key, and sends it back. The client decrypts the symmetric key, which is then used to encrypt and decrypt file content.
- **File Encryption & Transfer**: The client encrypts the file in chunks and sends it to the server. The server decrypts each chunk and saves the file in the client's directory.
- **Checksum Validation**: After the file is received, the server calculates the checksum and sends it to the client. The client computes its checksum and compares the two values. If they do not match, the file is resent up to three times.
- **Reconnection**: If the client is registered, they can reconnect to send more files. A new symmetric key is generated for each session.

### Checksum Calculation
To ensure file integrity, the checksum is calculated by splitting the file's checksum value into 8 chunks and packing it into 4 bytes. This checksum value is used for cyclic redundancy checks (CRC).

## Diagrams
### Registration and Reconnection Flow

**Client** 

![client_full_flow](https://user-images.githubusercontent.com/81361291/225738731-ecf6025c-4ea3-4428-8c41-6d4aab872341.PNG)

**Server**

![server_full_flow](https://user-images.githubusercontent.com/81361291/225738025-daef159a-1eab-4927-bd17-0b041b1bef58.PNG)

### File Already on the Server

**Client**

![error_full_flow_clinet](https://user-images.githubusercontent.com/81361291/225739226-58af1087-db42-4084-9306-e114da84f601.PNG)

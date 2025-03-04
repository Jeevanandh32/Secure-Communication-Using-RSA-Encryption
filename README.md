# Secure-Communication-Using-RSA-Encryption
# Introduction
This project aims to establish a secure communication channel between two Ubuntu VMs using RSA encryption. The process involves generating RSA key pairs, exchanging public keys, and implementing encrypted message transmission using socket programming. The chat application ensures confidentiality by encrypting messages before transmission and decrypting them upon receipt.

# Step-by-Step Approach
# Step 1: Setup Ubuntu VMs
Both VMs must have Python installed along with the required cryptographic library (pycryptodome). The following commands install the necessary dependencies:

     sudo apt update && sudo apt install python3 python3-pip
     pip install pycryptodome

This ensures that Python and the RSA encryption libraries are available on both machines.
# Step 2: Generate RSA Key Pair (On Both VMs)
Each VM must generate a unique RSA key pair consisting of a private and a public key. This is achieved using the generate_keys.py

Running this script using python3 generate_keys.py generates two files:
private.pem (Private Key)
public.pem (Public Key)

The private key is kept secure on the VM, while the public key is shared with the other VM
# Step 3: Exchange Public Keys
Each VM must acquire the public key of the other VM for encryption. This can be done manually or through an automated exchange system.

Automated Public Key Exchange:
The exchange process is facilitated through a socket-based key-sharing system.
After running the server and client scripts, both VMs have:
The other VM’s public key stored as client_public.pem or server_public.pem.
# Step 4: Implement Secure Communication Using Sockets
Once the key exchange is complete, the VMs can securely communicate using RSA encryption.
# Step 5: Running the Application
Once all scripts are ready:
On Server VM, run:

    python3 server.py
On Client VM, run:

    python3 client.py

Communication continues until either party sends "exit".

# Step 6: Erase Keys After Chat Ends
To enhance security, the exchanged public keys are deleted after the session.

Manual Removal

    rm client_public.pem server_public.pem
Automated Removal (Python)
 
    python
    import os
    os.remove("client_public.pem")
    os.remove("server_public.pem")

# Conclusion
This project implements a secure messaging system using RSA encryption, ensuring confidentiality and protection against eavesdropping. By following the structured approach of key generation, exchange, and encryption-based communication, a robust and secure chat application is successfully created between two VMs.

# Results
![WhatsApp Image 2025-02-13 at 02 53 08_5af91ae3](https://github.com/user-attachments/assets/5f50b305-8b4d-4e1a-863a-7ba3d4245db6)

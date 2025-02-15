import socket
import hashlib
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Define the hashed password for authentication
PASSWORD_HASH = hashlib.sha256("your_secret_password".encode()).hexdigest()

# Load RSA private key for decryption
private_key = RSA.import_key(open("private.pem", "rb").read())
cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)

# Create a socket and bind to the server IP and port
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("192.168.1.100", 12345))  # Change to your static server IP
server.listen(1)

print("Waiting for Connection...")
conn, addr = server.accept()
print("Connected by", addr)

# Authentication Step
conn.sendall("Enter Password: ".encode())  # Prompt for password

client_password = conn.recv(1024).decode().strip()

# Check password hash
if hashlib.sha256(client_password.encode()).hexdigest() != PASSWORD_HASH:
    conn.sendall("Authentication Failed. Closing Connection.".encode())
    conn.close()
    print("\nAuthentication Failed. Closing Connection.")
    server.close()
    exit()

conn.sendall("Authentication Successful. Proceeding with secure communication.".encode())
print("\nAuthentication Successful. Secure Communication Established.")

# Load client public key for encryption
client_public_key = RSA.import_key(open("client_public.pem", "rb").read())
cipher_rsa_encrypt = PKCS1_OAEP.new(client_public_key)

# Secure Communication Loop
while True:
    encrypted_msg = conn.recv(4096)
    
    if not encrypted_msg:
        break

    print("\nEncrypted Message Received:", encrypted_msg.decode())

    try:
        decrypted_msg = cipher_rsa_decrypt.decrypt(base64.b64decode(encrypted_msg)).decode()
        print("\nDecrypted Message:", decrypted_msg)
    except ValueError:
        print("\nDecryption Failed: Incorrect ciphertext received.")
        continue

    # Exit condition
    if decrypted_msg.lower() == "exit":
        break

    # Server's reply
    response = input("\nReply: ")
    encrypted_response = base64.b64encode(cipher_rsa_encrypt.encrypt(response.encode())).decode()
    
    print("\nEncrypted Response Sent:", encrypted_response)
    conn.sendall(encrypted_response.encode())

conn.close()
server.close()

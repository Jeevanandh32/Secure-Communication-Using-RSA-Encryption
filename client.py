import socket
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Load RSA public key for encryption
server_public_key = RSA.import_key(open("server_public.pem", "rb").read())
cipher_rsa_encrypt = PKCS1_OAEP.new(server_public_key)

# Load RSA private key for decryption
private_key = RSA.import_key(open("private.pem", "rb").read())
cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)

# Create a socket and connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("192.168.1.100", 12345))  # Change to your static server IP

# Receive password prompt and enter password
auth_prompt = client.recv(1024).decode()
print(auth_prompt)

password = input("Enter Password: ")
client.sendall(password.encode())

# Receive authentication response
auth_response = client.recv(1024).decode()
print(auth_response)

if "failed" in auth_response.lower():
    client.close()
    exit()

# Secure Communication Loop
while True:
    message = input("\nEnter message: ")
    
    encrypted_msg = base64.b64encode(cipher_rsa_encrypt.encrypt(message.encode())).decode()
    print("\nEncrypted Message Sent:", encrypted_msg)
    client.sendall(encrypted_msg.encode())

    if message.lower() == "exit":
        break

    encrypted_reply = client.recv(4096).decode()
    
    try:
        decrypted_reply = cipher_rsa_decrypt.decrypt(base64.b64decode(encrypted_reply)).decode()
        print("\nDecrypted Response:", decrypted_reply)
    except ValueError:
        print("\nDecryption Failed: Incorrect ciphertext received.")
        continue

client.close()

import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# Load server's public key
server_public_key = RSA.import_key(open("server_public.pem").read())
cipher_rsa_encrypt = PKCS1_OAEP.new(server_public_key)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("server_ip", 12345))  # Replace with actual IP

while True:
    message = input("Enter message: ")

    # Encrypt message
    encrypted_msg = base64.b64encode(cipher_rsa_encrypt.encrypt(message.encode()))
    client.sendall(encrypted_msg)

    if message.lower() == "exit":
        break

    # Load private key to decrypt response
    private_key = RSA.import_key(open("private.pem").read())
    cipher_rsa_decrypt = PKCS1_OAEP.new(private_key)
    
    encrypted_reply = client.recv(1024)
    decrypted_reply = cipher_rsa_decrypt.decrypt(base64.b64decode(encrypted_reply)).decode()
    print(f"Server: {decrypted_reply}")

client.close()

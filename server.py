import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# Load private key
private_key = RSA.import_key(open("private.pem").read())
cipher_rsa = PKCS1_OAEP.new(private_key)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 12345))  # Change IP if needed
server.listen(1)

print("Waiting for connection...")
conn, addr = server.accept()
print("Connected by", addr)

while True:
    encrypted_msg = conn.recv(1024)
    if not encrypted_msg:
        break

    # Decrypt message
    decrypted_msg = cipher_rsa.decrypt(base64.b64decode(encrypted_msg)).decode()
    print(f"Client: {decrypted_msg}")

    if decrypted_msg.lower() == "exit":
        break

    response = input("Reply: ")
    
    # Encrypt response using client's public key
    client_public_key = RSA.import_key(open("client_public.pem").read())
    cipher_rsa_encrypt = PKCS1_OAEP.new(client_public_key)
    
    encrypted_response = base64.b64encode(cipher_rsa_encrypt.encrypt(response.encode()))
    conn.sendall(encrypted_response)

conn.close()
server.close()

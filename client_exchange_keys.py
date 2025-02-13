import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("server_ip", 12345))  # Replace with actual IP

# Receive server's public key
server_public_key = client.recv(4096)
with open("server_public.pem", "wb") as pub_file:
    pub_file.write(server_public_key)

# Load client's public key and send it
client_public_key = open("public.pem", "rb").read()
client.sendall(client_public_key)

print("Public key exchange completed.")
client.close()

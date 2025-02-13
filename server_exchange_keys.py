import socket

# Read server's public key
server_public_key = open("public.pem", "rb").read()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 12345))
server.listen(1)
print("Waiting for client...")

conn, addr = server.accept()
print(f"Connected to {addr}")

# Send server's public key
conn.sendall(server_public_key)

# Receive client's public key
client_public_key = conn.recv(4096)
with open("client_public.pem", "wb") as pub_file:
    pub_file.write(client_public_key)

print("Public key exchange completed.")
conn.close()
server.close()

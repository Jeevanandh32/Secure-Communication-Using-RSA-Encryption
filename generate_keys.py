from Crypto.PublicKey import RSA

# Generate RSA key pair
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save private key
with open("private.pem", "wb") as priv_file:
    priv_file.write(private_key)

# Save public key
with open("public.pem", "wb") as pub_file:
    pub_file.write(public_key)

print("RSA Key Pair Generated.")

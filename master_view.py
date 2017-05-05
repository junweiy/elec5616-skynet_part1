import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES

def decrypt_valuables(f):
    # Define unpadding function for CBC mode
    unpad = lambda s: s.decode("ascii")[0:-ord(s.decode("ascii")[-1])]
    # First component is iv of 16 bytes
    iv = f[:16]
    # Second component is encrypted AES key of 256 bytes
    encrypted_aes_key = f[16:16+256]
    # Last component if encrypted data
    encrypted_data = f[16+256:]
    # AES key will be recovered first with RSA private key
    key_file = open('privateKey.pem')
    private_key = RSA.importKey(key_file.read())
    key_file.close()
    # Decrypt AES key with RSA private key
    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)
    # Initialise AES cipher
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # Decrypt actual data
    decoded_text = unpad(aes_cipher.decrypt(encrypted_data))
    print(decoded_text)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)

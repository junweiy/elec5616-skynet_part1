import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS

# Sign hash of file with generated private key
def sign_file(f):
    key_file = open('privateKey.pem')
    private_key = RSA.importKey(key_file.read())
    key_file.close()
    h = SHA256.new()
    h.update(f)
    signature = PKCS1_PSS.new(private_key).sign(h)
    # signature and message will be returned
    return signature + f


if __name__ == "__main__":
    # Genereate 256-byte RSA key pairs if not exist
    if not os.path.exists("privateKey.pem") or not os.path.exists("publicKey.pem"):
        new_key = RSA.generate(2048)
        private_key = new_key.exportKey(format='PEM',pkcs=1)
        public_key = new_key.publickey().exportKey(format='PEM',pkcs=1)
        f = open('privateKey.pem', 'wb')
        f.write(private_key)
        f.close()
        f = open('publicKey.pem', 'wb')
        f.write(public_key)
        f.close()

    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)

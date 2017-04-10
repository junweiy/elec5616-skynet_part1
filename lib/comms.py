import struct
import random

from Crypto.Cipher import AES
from Crypto.Random import random as rd
from Crypto.Hash import HMAC, SHA256

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.hmac = None
        self.token = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Initialise PRNG with shared_hash as seed
        random.seed(shared_hash)
        # Generate random initialisation vector with length equal to block size
        iv_string = "{:016b}".format(random.getrandbits(AES.block_size))
        iv = bytes(iv_string, "ascii")
        # Chosen AES as cipher in Cipher Feedback mode with first half of shared hash as 32 bytes key
        self.cipher = AES.new(shared_hash[:32], AES.MODE_CFB, iv)
        # Initialise HMAC with second half of shared hash as the secret
        self.hmac = HMAC.new(str(shared_hash[33:]).encode("ascii"), digestmod=SHA256)


    def send(self, data):
        # Randomly generate one-time session token to prevent replay attack when cipher and HMAC exist
        if self.cipher and not(self.token):
            self.token = SHA256.new(bytes(str(rd.getrandbits(16)), "ascii")).hexdigest().encode("ascii")
        if self.cipher:
            self.hmac.update(self.token)
            self.hmac.update(data)
            encrypted_token = self.cipher.encrypt(self.token)
            token_len = struct.pack('H', len(encrypted_token))
            encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data
        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        if self.hmac:
            self.conn.sendall(token_len)
            self.conn.sendall(encrypted_token)
            hmac_digest = struct.pack('64s', bytes(self.hmac.hexdigest(), "ascii"))
            self.conn.sendall(hmac_digest)
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        if self.cipher:
            token_len_packed = self.conn.recv(struct.calcsize('H'))
            token_len_unpacked = struct.unpack('H', token_len_packed)
            token_len = token_len_unpacked[0]
            encrypted_token = self.conn.recv(token_len)
            token = self.cipher.decrypt(encrypted_token)
            if not(self.token):
                self.token = token
            self.hmac.update(token)
        # Decode the data's length from an unsigned two byte int ('H')
        if self.hmac:
            hmac_packed = self.conn.recv(struct.calcsize('64s'))
            unpacked_hmac = struct.unpack('64s', hmac_packed)
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)

        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)
            hmac_digest = unpacked_hmac[0]
            self.hmac.update(data)
            if self.hmac.hexdigest() != hmac_digest.decode("ascii"):
                print('HMAC verification failed')
            if self.token != token:
                print('Session token incorrect')
            if not(self.token):
                self.token = data
                print("*", type(self.token))
                return
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()

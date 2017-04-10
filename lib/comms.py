import struct
import random

from Crypto.Cipher import AES
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
        self.cipher = AES.new(shared_hash[:32], AES.MODE_CFB, iv)
        self.hmac = HMAC.new(str(shared_hash[33:]).encode("ascii"), digestmod=SHA256)

    def send(self, data):
        if self.cipher:
            self.hmac.update(data)
            encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        if self.hmac:
            pkt_len = struct.pack('H64s', len(encrypted_data), bytes(self.hmac.hexdigest(), "ascii"))
        else:
            pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        if self.hmac:
            pkt_len_packed = self.conn.recv(struct.calcsize('H64s'))
            unpacked_contents = struct.unpack('H64s', pkt_len_packed)
        else:
            pkt_len_packed = self.conn.recv(struct.calcsize('H'))
            unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]
        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)
            hmac_digest = unpacked_contents[1]
            self.hmac.update(data)
            if self.hmac.hexdigest() != hmac_digest.decode("ascii"):
                print('HMAC verification failed')
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()

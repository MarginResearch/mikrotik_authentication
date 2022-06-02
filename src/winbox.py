import elliptic_curves, encryption
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.Util.Padding import pad, unpad
import time, socket, binascii, secrets, argparse

class Winbox:
    def __init__(self, host: str, port: int = 8291):
        self.host = host
        self.port = port
        self.username = 'admin'
        self.password = ''
        self.socket = None
        self.stage = -1
        self.w = elliptic_curves.WCurve()
        self.s_a = b''
        self.x_w_a = b''
        self.x_w_a_parity = -1
        self.x_w_b = b''
        self.x_w_b_parity = -1
        self.j = b''
        self.z = b''
        self.secret = b''
        self.client_cc = b''
        self.server_cc = b''
        self.i = b''
        self.msg = b''
        self.resp = b''
        self.send_aes_key = b''
        self.send_hmac_key = b''
        self.receive_aes_key = b''
        self.receive_hmac_key = b''

    def close(self):
        self.socket.close()
        print("Session terminated")

    # effectively ECPESVDP-SRP-A with a small modification of hashing both public keys together for h
    def gen_shared_secret(self, salt):
        self.i = self.w.gen_password_validator_priv(self.username, self.password, salt)
        x_gamma, gamma_parity = self.w.gen_public_key(self.i)
        v = self.w.redp1(x_gamma, 1) # parity = 1 inverts the y coordinate result
        w_b = self.w.lift_x(int.from_bytes(self.x_w_b, "big"), self.x_w_b_parity)
        w_b += v
        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        pt = int.from_bytes(self.i, "big") * int.from_bytes(self.j, "big")
        pt += int.from_bytes(self.s_a, "big")
        pt = self.w.finite_field_value(pt) # mod by curve order to ensure the result is a point within the finite field
        pt = pt * w_b
        self.z, _ = self.w.to_montgomery(pt)
        self.secret = encryption.get_sha2_digest(self.z)

    # performs authentication in linear manner
    # looped to retry if any errors occur
    def auth(self, username: str, password: str):

        def open_socket():
            print("opening socket")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))
            s.settimeout(5)
            self.socket = s
            self.stage = 0

        # simple ECPEPKGP-SRP-A algorithm to generate public key
        def public_key_exchange():
            self.s_a = secrets.token_bytes(32)
            self.x_w_a, self.x_w_a_parity = self.w.gen_public_key(self.s_a)
            if not w.check(self.w.lift_x(int.from_bytes(self.x_w_a, "big"), self.x_w_a_parity)):
                self.stage = -1
            self.msg = username.encode('utf-8') + b'\x00'
            self.msg += self.x_w_a + int(self.x_w_a_parity).to_bytes(1, "big")
            self.msg = len(self.msg).to_bytes(1, "big") + b'\x06' + self.msg
            self.stage = 1

        # handles server repsonse and performs ECPESVDP-SRP-A to compute z
        # uses z for Cc and formats response to confirm shared secret
        def confirmation():
            resp_len = self.resp[0]
            self.resp = self.resp[2:]
            if len(self.resp) != int(resp_len):
                print("Error: challenge response corrupted. Retrying...")
                self.stage = -1
                return
            self.x_w_b = self.resp[:32]
            self.x_w_b_parity = self.resp[32]
            salt = self.resp[33:]
            if len(salt) != 0x10:
                print("Error: challenge response corrupted. Retrying...")
                self.stage = -1
                return
            self.gen_shared_secret(salt)
            self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
            self.client_cc = encryption.get_sha2_digest(self.j + self.z)
            self.msg = len(self.client_cc).to_bytes(1, "big") + b'\x06' + self.client_cc
            self.stage = 2
            
        self.username = username
        self.password = password
        w = elliptic_curves.WCurve()
                
        while True:
            if self.stage == -1: 
                if self.socket != None: self.socket.close()
                open_socket()
            elif self.stage == 0:
                public_key_exchange()
            elif self.stage == 1: 
                confirmation()
            elif self.stage == 2:
                self.server_cc = encryption.get_sha2_digest(self.j + self.client_cc + self.z)
                if self.resp[2:] != self.server_cc:
                    print("Error: mismatched confirmation key. Retrying..")
                    self.stage = -1
                else:   
                    self.stage = 3
            elif self.stage == 3:
                print("Connection successful")
                self.send_aes_key, self.receive_aes_key, self.send_hmac_key, self.receive_hmac_key = encryption.gen_stream_keys(False, self.secret)
                break
                    
            if self.msg != b'' and self.socket != None:
                self.socket.send(self.msg)
                self.msg = b''
                try:
                    self.resp = self.socket.recv(1024)
                except socket.timeout:
                    print("Error: server timeout. Retrying...")
                    self.stage = -1

        return 0

    # performs mac-then-encrypt with the previously computed keys
    # formats response, which is a series of 0xff length messages if len(msg) > 0xff
    # adds modified padding which is similar to PKCS-7
    def send(self, msg: bytes, iv: bytes = b''):
        assert self.send_aes_key != b'', print("sending AES key not set, initialize before sending a message")
        assert self.send_hmac_key != b'', print("sending HMAC key not set, initialize before sending a message")
        assert msg[0:2] == b'M2', print("The message should begin with 'M2' and not include the prepended length")
        hmac = HMAC.new(self.send_hmac_key, b'', SHA1)
        hmac.update(msg)
        h = hmac.digest()
        if iv != b'':
            assert len(iv) == 0x10, print("AES CBC IV must be 16 bytes")
        else: 
            iv = secrets.token_bytes(0x10)
        aes = AES.new(self.send_aes_key, AES.MODE_CBC, iv)
        # modify padding input 
        pad_byte = 0xf - len(msg + h) % 0x10
        msg = pad(msg + h + pad_byte.to_bytes(1, "big"), 0x10)
        msg = aes.encrypt(msg)
        msg_len = len(msg)
        msg = msg_len.to_bytes(2, "big") + iv + msg
        if msg_len >= 0xff:  msg_len = 0xff
        else:                msg_len += 0x12
        index = b'\x06'
        self.msg = b''
        while True:
            self.msg += msg_len.to_bytes(1, "big") + index
            if len(msg) >= 0xff:
                self.msg += msg[:0xff]
                msg = msg[0xff:]
            else:
                self.msg += msg
                break
            index = b'\xff'
            if len(msg) >= 0xff:
                msg_len = 0xff
            else:
                msg_len = len(msg)
        self.socket.send(self.msg)
        return self.receive()
    
    # reassembles the original encrypted data 0xff chunk by 0xff chunk 
    # decrypts with altered padding and validates data using HMAC 
    def receive(self):
        try:
            ct = self.socket.recv(1024)
        except socket.timeout: 
            return None
        assert self.receive_aes_key != b'', print("receiving AES key not set, initialize before receiving a message")
        assert self.receive_hmac_key != b'', print("receiving HMAC key not set, initialize before receiving a message")
        assert ct[1] == 6, print("Unknown handler received (expected 0x6), terminating")
        self.resp = b''
        ct_assembled = b''
        while True:
            ct = ct[2:]
            if len(ct) >= 0xff:
                ct_assembled += ct[:0xff]
                ct = ct[0xff:]
            else:
                ct_assembled += ct
                break   
        ct_assembled = ct_assembled[2:]
        iv = ct_assembled[:0x10]
        aes = AES.new(self.receive_aes_key, AES.MODE_CBC, iv)
        self.resp = aes.decrypt(ct_assembled[0x10:])
        if self.resp[-1] != 0:
            self.resp = unpad(self.resp, AES.block_size)
        self.resp = self.resp[:-1]
        hmc = self.resp[-20:]
        self.resp = self.resp[:-20]
        hmac = HMAC.new(self.receive_hmac_key, b'', SHA1)
        hmac.update(self.resp)
        assert hmac.digest() == hmc, print("Error, HMAC failed to authenticate packet data. Exiting")
        return self.resp

if __name__ == "__main__":
    args = argparse.ArgumentParser(description='Winbox Client')
    args.add_argument("-a", "--address", help="Winbox server address", required=True)
    args.add_argument("-u", "--username", help="username", required=True)
    args.add_argument("-p", "--password", help="password", default="")
    args = vars(args.parse_args())
    w = Winbox(args["address"])
    w.auth(args["username"], args["password"])
    # send test request, which is the deterministic first request issued by Winbox.exe 
    msg = b'M2\x05\x00\xff\x01\x06\x00\xff\t\x01\x07\x00\xff\t\x07\x01\x00\xff\x88\x02\x00\r\x00\x00\x00\x04\x00\x00\x00\x02\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00'
    resp = w.send(msg)
    # validate successful decryption
    print("Received response: ")
    print(resp)
    w.close()
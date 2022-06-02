import elliptic_curves, encryption
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.Util.Padding import pad, unpad
import socket, select, binascii, socketserver, sys, threading, _thread, secrets, argparse
import ecdsa

PORT = 8291
dat_filepath = ""
p_lock = threading.Lock()

def print_with_lock(p):
    p_lock.acquire()
    if type(p) == tuple:
        for i in p:
            print(i, end= " ")
        print()
    else: print(p)
    p_lock.release()

# parses the /rw/store/user.dat file for usernames, salts, and password validators
def parse_userdat(dat_filepath):
    def get_bytes(msg: bytes, target: bytes):
        if msg.find(target) < 0: return -1
        length = msg[msg.find(target) + 4]
        data = msg[msg.find(target) + 5 : msg.find(target) + 5 + length]
        return data

    try: f = open(dat_filepath, 'rb')
    except Exception as e: print_with_lock(e)
    data = f.read()
    users = {}
    while data:
        length = int.from_bytes(data[0:2], "little")
        msg = data[2:length]
        assert msg[0:2] == b"M2", print_with_lock("Incorrect message header")
        username = get_bytes(msg, b"\x01\x00\x00\x21").decode('utf-8')
        salt = get_bytes(msg, b"\x20\x00\x00\x31")
        v = get_bytes(msg, b"\x21\x00\x00\x31")
        if username == -1 or salt == -1 or v == -1:
            return -1
        users[username] = [salt, v]
        data = data[length:]

    return users

class WinboxServer():
    def __init__(self, addr: tuple):
        self.username = 'admin'
        self.password = ''
        self.conn_addr = addr
        self.stage = 0
        self.w = elliptic_curves.WCurve()
        self.x_w_a = b''
        self.x_w_a_parity = -1
        self.s_b = b''
        self.x_w_b = b''
        self.x_w_b_parity = -1
        self.j = b''
        self.z = b''
        self.secret = b''
        self.client_cc = b''
        self.server_cc = b''
        self.i = b''
        self.x_gamma = b''
        self.gamma_parity = -1
        self.msg = b''
        self.resp = b''
        self.send_aes_key = b''
        self.send_hmac_key = b''
        self.receive_aes_key = b''
        self.receive_hmac_key = b''

        # import users, salts, and password validators
        users = parse_userdat(dat_filepath)
        if users == -1: 
            print_with_lock("failed to parse user.dat")
            return -1
        else: 
            self.users = users
    
    # handles requests based on the handshake stage 
    def process_msg(self):
        self.msg = b''
        if self.resp == b'': return 0
        message_len = self.resp[0]
        if self.resp[1] != 0x6: # destination handler in mproxy
            print_with_lock("Incorrect destination handler") 
            return -1
        if message_len == len(self.resp[2:]):
            if self.stage == 0: # initial handshake message from client 
                self.resp = self.resp[2:]
                return self.public_key_exchange()
            elif self.stage == 1: # client confirmation code 
                self.resp = self.resp[2:]
                if len(self.resp) != 0x20:
                    print_with_lock("invalid client confirmation code length")
                    return -1
                self.client_cc = self.resp
                return self.gen_shared_secret()
            if self.stage == 2:
                self.receive() # iv + encrypted message 
                print_with_lock((self.conn_addr[0] + ":" + str(self.conn_addr[1]) + \
                    " received decrytped message: ", self.resp, "\n"))
                return self.mock_response()

    # performs ECPEPKGP-SRP-B to generate a password-entangled public key
    def gen_x_w_b_key(self):
        pub = self.w.multiply_by_g(int.from_bytes(self.server_private, "big"))
        gamma = self.w.redp1(self.x_gamma, 0)
        pt = gamma + pub
        self.x_w_b, self.x_w_b_parity = self.w.to_montgomery(pt)

    # validates the request user exists in user.dat and retrieves associated salt, x_gamma
    # generates a server public key and formats response
    def public_key_exchange(self):
        nullbyte = self.resp.find(b'\x00')
        self.username = (self.resp[:nullbyte]).decode("utf-8")
        self.x_w_a = self.resp[nullbyte + 1:]
        if not self.check_username():
            print_with_lock("invalid username")
            return -1
        if len(self.x_w_a) != 0x21: 
            print("invalid client public key length")
            return -1

        self.stage = 1
        self.x_w_a_parity = self.x_w_a[-1]
        self.x_w_a = self.x_w_a[:-1]
        self.server_private = secrets.token_bytes(32)
        self.gen_x_w_b_key()
        self.msg = self.x_w_b + int(self.x_w_b_parity).to_bytes(1, "big") + self.salt
        self.msg = len(self.msg).to_bytes(1, "big") + b'\x06' + self.msg
        return self.msg

    # check username dictionary for request username and sets salt, x_gamma, gamma_parity
    def check_username(self): 
        if self.username in self.users:
            self.salt, self.x_gamma = self.users[self.username]
            self.gamma_parity = self.x_gamma[-1]
            self.x_gamma = self.x_gamma[:-1]
            return 1
        return 0

    # effectively ECPESVDP-SRP-B with a small modification of hashing both public keys together for h
    def gen_shared_secret(self):
        self.i = self.w.gen_password_validator_priv(self.username, self.password, self.salt)
        x_gamma, gamma_parity = self.w.gen_public_key(self.i)
        if self.x_gamma != x_gamma: 
            print("error calculating password validator input") 
            return -1
        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        gamma = self.w.lift_x(int.from_bytes(x_gamma, "big"), 1)
        gamma *= int.from_bytes(self.j, "big")
        w_a = self.w.lift_x(int.from_bytes(self.x_w_a, "big"), self.x_w_a_parity)
        pt = gamma + w_a
        pt *= int.from_bytes(self.server_private, "big")
        self.z = self.w.to_montgomery(pt)[0]
        self.secret = encryption.get_sha2_digest(self.z)
        cc = encryption.get_sha2_digest(self.j + self.z)
        if cc != self.client_cc:
            print_with_lock("invalid client cc, check username and password")
            return -1
        print_with_lock(self.conn_addr[0] + ":" + str(self.conn_addr[1]) + " login successful")
        self.stage = 2
        self.send_aes_key, self.receive_aes_key, self.send_hmac_key, self.receive_hmac_key = encryption.gen_stream_keys(True, self.secret)
        self.server_cc = encryption.get_sha2_digest(self.j + self.client_cc + self.z)
        self.msg = len(self.server_cc).to_bytes(1, "big") + b'\x06' + self.server_cc
        return self.msg

    # send a deterministic repsonse for the first Winbox.exe client request
    # this validates encryption and decryption, as Winbox accepts the mock response and does not repeat the first request
    def mock_response(self):
        if self.resp == b'M2\x05\x00\xff\x01\x06\x00\xff\t\x01\x07\x00\xff\t\x07\x01\x00\xff\x88\x02\x00\r\x00\x00\x00\x04\x00\x00\x00\x02\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00':
            return self.send(b'M2\x01\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x02\x00\xff\x88\x02\x00\r\x00\x00\x00\x04\x00\x00\x00&\x00\x00\x00\x1c\x00\x00\x00\x13\x00\x00\x00\x0f\x00\x00\t\x00\x10\x00\x00\t\x00\x03\x00\xff\t\x02\x0b\x00\x00\x08\xfe\xff\x05\x00\x06\x00\xff\t\x01\x16\x00\x00!\x043.30\x17\x00\x00!\x03x86\x15\x00\x00!\x03x86\x11\x00\x00!\x04i386')
        else: 
            print_with_lock(self.conn_addr[0] + ":" + str(self.conn_addr[1]) + " no response available")
            return -1

    # performs mac-then-encrypt with the previously computed keys
    # formats response, which is a series of 0xff length messages if len(msg) > 0xff
    # adds modified padding which is similar to PKCS-7
    def send(self, msg: bytes, iv: bytes = b''):
        assert self.send_aes_key != b'', print_with_lock("sending AES key not set, initialize before sending a message")
        assert self.send_hmac_key != b'', print_with_lock("sending HMAC key not set, initialize before sending a message")
        assert msg[0:2] == b'M2', print_with_lock("The message should begin with 'M2' and not include the prepended length")
        hmac = HMAC.new(self.send_hmac_key, b'', SHA1)
        hmac.update(msg)
        h = hmac.digest()
        if iv != b'':
            assert len(iv) == 0x10, print_with_lock("AES CBC IV must be 16 bytes")
        else: 
            iv = secrets.token_bytes(0x10)
        aes = AES.new(self.send_aes_key, AES.MODE_CBC, iv)
        # modify padding 
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
        return self.msg

    # reassembles the original encrypted data 0xff chunk by 0xff chunk 
    # decrypts with altered padding and validates data using HMAC 
    def receive(self):
        ct = self.resp
        assert self.receive_aes_key != b'', print_with_lock("receiving AES key not set, initialize before receiving a message")
        assert self.receive_hmac_key != b'', print_with_lock("receiving HMAC key not set, initialize before receiving a message")
        assert ct[1] == 6, print_with_lock("Unknown handler received (expected 0x6), terminating")
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
        assert hmac.digest() == hmc, print_with_lock("Warning, decrypted HMAC failed to authenticate packet data")
        return self.resp

def new_thread(c, addr: tuple):
    c.settimeout(5)
    s = WinboxServer(addr)
    while True:
        try:
            s.resp = c.recv(1024)
            msg = s.process_msg()
        except socket.timeout:
            print_with_lock(addr[0] + ":" + str(addr[1]) + " timeout")
            c.close()
            exit(0)
        if msg == -1: 
            print_with_lock(addr[0] + ":" + str(addr[1]) + " terminating connection")
            c.close()
            exit(0)
        if msg != b'' and msg != 0: c.send(msg)

if __name__ == "__main__":
    args = argparse.ArgumentParser(description='Winbox Server')
    args.add_argument("-a", "--address", help="host address", required=True)
    args.add_argument("-d", "--data", help="user.dat file path", required=True)
    args = vars(args.parse_args())
    dat_filepath = args["data"]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((args["address"], PORT))
    s.listen(5)
    while True:
        c, addr = s.accept()
        print("Connected to: " + addr[0] + ":" + str(addr[1]))
        _thread.start_new_thread(new_thread, (c, addr))
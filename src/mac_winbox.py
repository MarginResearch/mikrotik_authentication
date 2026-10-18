import socket, struct, secrets, argparse, subprocess, re
import elliptic_curves, encryption
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Util.Padding import pad, unpad

class MacWinbox:
    def __init__(self, target_mac: str):
        # 极简获取本机 MAC，用于二层封包
        iface = re.search(r'dev\s+(\S+)', subprocess.check_output(['ip', 'route', 'get', '8.8.8.8']).decode('utf-8')).group(1)
        self.local_mac = bytes.fromhex(open(f'/sys/class/net/{iface}/address').read().strip().replace(':', ''))
        self.target_mac = bytes.fromhex(target_mac.replace(':', ''))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        self.session_id = secrets.randbits(16)
        self.w = elliptic_curves.WCurve()
        self.c_sent = 0
        self.c_recv = 0
        self.msg = b''
        self.resp = b''

        self.send_aes_key = b''
        self.send_hmac_key = b''
        self.receive_aes_key = b''
        self.receive_hmac_key = b''

    def close(self):
        self.sock.close()
        print("Session terminated")

    def send_raw(self, msg_type, payload, counter=None):
        if counter is None: counter = self.c_sent
        pkt = struct.pack('!BB', 1, msg_type) + self.local_mac + self.target_mac + \
              struct.pack('!H', self.session_id) + struct.pack('!H', 0x0f90) + struct.pack('!I', counter) + payload
        self.sock.sendto(pkt, ('255.255.255.255', 20561))
        if msg_type == 1: self.c_sent += len(payload)

    def recv_raw(self, need_ack=False):
        while True:
            data, _ = self.sock.recvfrom(4096)
            if len(data) < 22 or data[2:8] != self.target_mac: continue

            msg_type = data[1]
            payload = data[22:]

            if msg_type == 2: # 纯 Ack
                if need_ack: return b''
                continue

            if msg_type == 1: # 数据包
                tlv_len = payload[0]
                tlv_data = payload[2:] if tlv_len == 0xff else payload[2:2+tlv_len]
                self.c_recv += len(payload)
                self.send_raw(2, b'', self.c_recv)
                return tlv_data

            if msg_type == 255:
                raise Exception("The remote host closed the connection")

    def gen_shared_secret(self, username, password, salt):
        self.i = self.w.gen_password_validator_priv(username, password, salt)
        x_gamma, gamma_parity = self.w.gen_public_key(self.i)
        v = self.w.redp1(x_gamma, 1)
        w_b = self.w.lift_x(int.from_bytes(self.x_w_b, "big"), self.x_w_b_parity)
        w_b += v
        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        pt = int.from_bytes(self.i, "big") * int.from_bytes(self.j, "big")
        pt += int.from_bytes(self.s_a, "big")
        pt = self.w.finite_field_value(pt)
        pt = pt * w_b
        self.z, _ = self.w.to_montgomery(pt)
        self.secret = encryption.get_sha2_digest(self.z)

    def auth(self, username: str, password: str):
        print("opening socket")
        self.send_raw(0, b'') # 1. Start Session
        self.recv_raw(need_ack=True) # 等待 Ack 并返回

        # 2. Client Hello
        self.s_a = secrets.token_bytes(32)
        while True:
            self.x_w_a, self.x_w_a_parity = self.w.gen_public_key(self.s_a)
            if self.w.check(self.w.lift_x(int.from_bytes(self.x_w_a, "big"), self.x_w_a_parity)): break

        msg = username.encode('utf-8') + b'\x00' + self.x_w_a + int(self.x_w_a_parity).to_bytes(1, "big")
        self.send_raw(1, struct.pack('!BB', len(msg), 0x06) + msg)

        # 3. Server Key
        resp = self.recv_raw()
        self.x_w_b = resp[:32]
        self.x_w_b_parity = resp[32]
        salt = resp[33:]
        self.gen_shared_secret(username, password, salt)

        self.j = encryption.get_sha2_digest(self.x_w_a + self.x_w_b)
        client_cc = encryption.get_sha2_digest(self.j + self.z)

        # 4. Client Confirm
        self.send_raw(1, struct.pack('!BB', len(client_cc), 0x06) + client_cc)

        # 5. Server Confirm
        self.recv_raw()

        self.send_aes_key, self.receive_aes_key, self.send_hmac_key, self.receive_hmac_key = encryption.gen_stream_keys(False, self.secret)
        print("Connection successful")
        return 0

    def send(self, msg: bytes):
        assert msg[0:2] == b'M2'
        hmac = HMAC.new(self.send_hmac_key, b'', SHA1)
        hmac.update(msg)
        h = hmac.digest()
        iv = secrets.token_bytes(0x10)
        aes = AES.new(self.send_aes_key, AES.MODE_CBC, iv)
        pad_byte = 0xf - len(msg + h) % 0x10
        msg = pad(msg + h + pad_byte.to_bytes(1, "big"), 0x10)
        msg = aes.encrypt(msg)

        tlv_payload = struct.pack('>H', len(msg)) + iv + msg
        self.send_raw(1, struct.pack('!BB', len(tlv_payload), 0x06) + tlv_payload)

        return self.receive()

    def receive(self):
        resp = self.recv_raw()
        msg_len = struct.unpack('>H', resp[0:2])[0]
        iv = resp[2:18]
        ciphertext = resp[18:18 + msg_len - 16]

        aes = AES.new(self.receive_aes_key, AES.MODE_CBC, iv)
        plain = aes.decrypt(ciphertext)

        # 忽略 MAC 尾部非标准填充，强行剥离
        if plain[-1] != 0:
            try:
                plain = unpad(plain, AES.block_size)
            except ValueError:
                pass

        plain = plain[:-1]
        return plain[:-20]

if __name__ == "__main__":
    args = argparse.ArgumentParser(description='MAC Winbox Client')
    args.add_argument("-a", "--address", help="Target MAC address", required=True)
    args.add_argument("-u", "--username", help="username", required=True)
    args.add_argument("-p", "--password", help="password", default="")
    args = vars(args.parse_args())

    w = MacWinbox(args["address"])
    w.auth(args["username"], args["password"])

    msg = b'M2\x05\x00\xff\x01\x06\x00\xff\t\x01\x07\x00\xff\t\x07\x01\x00\xff\x88\x02\x00\r\x00\x00\x00\x04\x00\x00\x00\x02\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00'
    resp = w.send(msg)

    print("Received response: ")
    print(resp)
    w.close()

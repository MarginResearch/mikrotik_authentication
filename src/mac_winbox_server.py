import socket, struct, secrets, argparse
import elliptic_curves, encryption
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Util.Padding import pad, unpad

PORT = 20561
CLIENT_TYPE = 0x0f90

class MacWinboxServer:
    def __init__(self, server_mac: str, dat_filepath: str):
        self.server_mac = bytes.fromhex(server_mac.replace(':', ''))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', PORT))

        self.w = elliptic_curves.WCurve()
        self.users = self.parse_userdat(dat_filepath)
        self.sessions = {}

    def parse_userdat(self, dat_filepath):
        def get_bytes(msg, target):
            if msg.find(target) < 0: return -1
            length = msg[msg.find(target) + 4]
            return msg[msg.find(target) + 5 : msg.find(target) + 5 + length]
        try: f = open(dat_filepath, 'rb')
        except Exception as e: print(e); return {}
        data = f.read()
        users = {}
        while data:
            length = int.from_bytes(data[0:2], "little")
            msg = data[2:length]
            users[get_bytes(msg, b"\x01\x00\x00\x21").decode('utf-8')] = [
                get_bytes(msg, b"\x20\x00\x00\x31"),
                get_bytes(msg, b"\x21\x00\x00\x31")
            ]
            data = data[length:]
        return users

    def build_header(self, msg_type, client_mac, session_id, counter):
        return struct.pack('!BB', 1, msg_type) + self.server_mac + client_mac + \
               struct.pack('!H', CLIENT_TYPE) + struct.pack('!H', session_id) + struct.pack('!I', counter)

    def run(self):
        print(f"MAC Winbox Server listening on UDP {PORT}")
        while True:
            data, addr = self.sock.recvfrom(4096)
            if len(data) < 22: continue

            dst_mac = data[8:14]
            if dst_mac != self.server_mac:
                continue

            msg_type = data[1]
            client_mac = data[2:8]
            session_id = struct.unpack('!H', data[16:18])[0]
            payload = data[22:]

            if msg_type == 2: continue

            mac_str = client_mac.hex(':')
            if mac_str not in self.sessions:
                self.sessions[mac_str] = {'stage': 0, 'c_recv': 0, 's_sent': 0}
            sess = self.sessions[mac_str]

            if msg_type == 0:
                # 收到 Start Session，强制重置状态
                self.sessions[mac_str] = {'stage': 0, 'c_recv': 0, 's_sent': 0}
                self.sock.sendto(self.build_header(2, client_mac, session_id, 0), addr)
                continue

            if msg_type == 1:
                tlv_len = payload[0]
                tlv_data = payload[2:] if tlv_len == 0xff else payload[2:2+tlv_len]

                sess['c_recv'] += (len(payload) if tlv_len == 0xff else tlv_len + 2)
                self.sock.sendto(self.build_header(2, client_mac, session_id, sess['c_recv']), addr)

                resp_payload = self.process_msg(sess, tlv_data)
                if resp_payload:
                    msg_payload = struct.pack('!BB', len(resp_payload), 0x06) + resp_payload
                    sess['s_sent'] += len(msg_payload)
                    pkt = self.build_header(1, client_mac, session_id, sess['s_sent']) + msg_payload
                    self.sock.sendto(pkt, addr)

    def process_msg(self, sess, data):
        stage = sess['stage']
        if stage == 0:
            nullbyte = data.find(b'\x00')
            sess['username'] = data[:nullbyte].decode('utf-8')
            sess['x_w_a'] = data[nullbyte+1:-1]
            sess['x_w_a_parity'] = data[-1]
            sess['salt'], sess['x_gamma'] = self.users[sess['username']]
            sess['x_gamma'] = sess['x_gamma'][:-1]

            sess['server_private'] = secrets.token_bytes(32)
            pub = self.w.multiply_by_g(int.from_bytes(sess['server_private'], "big"))
            gamma = self.w.redp1(sess['x_gamma'], 0)
            sess['x_w_b'], sess['x_w_b_parity'] = self.w.to_montgomery(gamma + pub)

            sess['stage'] = 1
            return sess['x_w_b'] + int(sess['x_w_b_parity']).to_bytes(1, "big") + sess['salt']

        elif stage == 1:
            sess['i'] = self.w.gen_password_validator_priv(sess['username'], '', sess['salt'])
            sess['j'] = encryption.get_sha2_digest(sess['x_w_a'] + sess['x_w_b'])
            gamma = self.w.lift_x(int.from_bytes(sess['x_gamma'], "big"), 1)
            gamma *= int.from_bytes(sess['j'], "big")
            w_a = self.w.lift_x(int.from_bytes(sess['x_w_a'], "big"), sess['x_w_a_parity'])
            pt = gamma + w_a
            pt *= int.from_bytes(sess['server_private'], "big")
            sess['z'] = self.w.to_montgomery(pt)[0]
            sess['secret'] = encryption.get_sha2_digest(sess['z'])

            sess['send_aes_key'], sess['receive_aes_key'], sess['send_hmac_key'], sess['receive_hmac_key'] = encryption.gen_stream_keys(True, sess['secret'])
            sess['server_cc'] = encryption.get_sha2_digest(sess['j'] + data + sess['z'])

            sess['stage'] = 2
            print(f"{sess['username']} login successful")
            return sess['server_cc']

        elif stage == 2:
            msg_len = struct.unpack('>H', data[0:2])[0]
            iv = data[2:18]
            cipher = data[18 : 18 + msg_len]

            aes = AES.new(sess['receive_aes_key'], AES.MODE_CBC, iv)
            plain = aes.decrypt(cipher)
            if plain[-1] != 0:
                try: plain = unpad(plain, AES.block_size)
                except ValueError: pass
            plaintext = plain[:-1][:-20]
            print(f"{sess['username']} received decrypted message: {plaintext}")

            resp = b'M2\x01\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x02\x00\xff\x88\x02\x00\r\x00\x00\x00\x04\x00\x00\x00&\x00\x00\x00\x1c\x00\x00\x00\x13\x00\x00\x00\x0f\x00\x00\t\x00\x10\x00\x00\t\x00\x03\x00\xff\t\x02\x0b\x00\x00\x08\xfe\xff\x05\x00\x06\x00\xff\t\x01\x16\x00\x00!\x043.30\x17\x00\x00!\x03x86\x15\x00\x00!\x03x86\x11\x00\x00!\x04i386'

            hmac = HMAC.new(sess['send_hmac_key'], b'', SHA1); hmac.update(resp)
            h = hmac.digest()
            iv_out = secrets.token_bytes(0x10)
            aes_out = AES.new(sess['send_aes_key'], AES.MODE_CBC, iv_out)
            pad_byte = 0xf - len(resp + h) % 0x10
            msg = pad(resp + h + pad_byte.to_bytes(1, "big"), 0x10)
            msg = aes_out.encrypt(msg)
            return struct.pack('>H', len(msg)) + iv_out + msg

if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("-m", "--mac", required=True, help="Server MAC")
    args.add_argument("-d", "--data", required=True, help="user.dat path")
    args = vars(args.parse_args())
    MacWinboxServer(args["mac"], args["data"]).run()

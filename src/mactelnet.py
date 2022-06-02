import asyncio
from struct import pack, unpack
import tty
import termios
import signal
import os
import argparse
import getpass
import uuid
import secrets
import time
import sys
import encryption
import elliptic_curves

BUF_SIZE = 1024
PACKET_HEADER_LEN = 0x16

SYS_VERSION = 1
SYS_CLIENT_TYPE = 0x15

SYS_START_SESSION = 0
SYS_DATA = 1
SYS_ACKNOWLEDGE = 2
SYS_END_SESSION = 255

CP_MAGIC = b'\x56\x34\x12\xff'

CP_BEGIN_AUTHENICATION = 0
CP_ENCRYPTION_KEY = 1
CP_PASSWORD = 2
CP_USERNAME = 3
CP_TERMINAL_TYPE = 4
CP_TERMINAL_WIDTH = 5
CP_TERMINAL_HEIGHT = 6
CP_END_AUTHENTICATION = 9

class ControlPacket():

    def __init__(self, cp_type: int = 0, data: bytes = b''):
        self.magic = CP_MAGIC
        self.packet_type = cp_type
        self.data = data
        self.data_length = len(self.data)

    # for debugging
    def __str__(self):
        if self.packet_type == CP_BEGIN_AUTHENICATION:
            output = "CP_BEGIN_AUTHENTICATION:"
        elif self.packet_type == CP_ENCRYPTION_KEY:
            output = "CP_ENCRYPTION_KEY:"
        elif self.packet_type == CP_PASSWORD:
            output = "CP_PASSWORD:"
        elif self.packet_type == CP_USERNAME:
            output = "CP_USERNAME:"
        elif self.packet_type == CP_TERMINAL_TYPE:
            output = "CP_TERMINAL_TYPE:"
        elif self.packet_type == CP_TERMINAL_WIDTH:
            output = "CP_TERMINAL_WIDTH:"
        elif self.packet_type == CP_TERMINAL_HEIGHT:
            output = "CP_TERMINAL_HEIGHT:"
        elif self.packet_type == CP_END_AUTHENTICATION:
            output = "CP_END_AUTHENTICATION:"
        else:
            output = "CP_UNKNOWN_TYPE:"

        output += " len=" + str(self.data_length)
        output += " data=" + self.data.hex()
        return output

    def to_bytes(self):
        header = pack(">4sbI",
                      CP_MAGIC,
                      self.packet_type,
                      self.data_length
                      )
        return header + self.data

    @classmethod
    def from_bytes(cls, data):
        cpacket = cls()
        magic, cpacket.packet_type, cpacket.data_length = unpack(">4sbI", data[:9])
        if magic != CP_MAGIC:
            print("error: parsing control packet with incorrect magic bytes", data)
        cp_end = 9+cpacket.data_length
        cpacket.data = data[9:cp_end]
        return data[cp_end:], cpacket

class Packet():

    def __init__(self):
        self.version = 1
        self.message_type = -1
        self.dst_mac = b''
        self.src_mac = b''
        self.client_type = 21
        self.session_id = -1
        self.message_type = -1
        self.byte_counter = -1
        self.data = b''
        self.control_packets = []

    # for debugging
    def __str__(self):
        output = "MACTelnet Packet v" + str(self.version) + " "
        if self.message_type == SYS_START_SESSION:
            output += "SYS_START_SESSION"
        elif self.message_type == SYS_DATA:
            output += "SYS_DATA"
        elif self.message_type == SYS_ACKNOWLEDGE:
            output += "SYS_ACKNOWLEDGE"
        elif self.message_type == SYS_END_SESSION:
            output += "SYS_END_SESSION"
        else:
            output += "SYS_UNKNOWN_TYPE"
        output += "\nsrc_mac="
        output += ":".join(self.src_mac.hex()[i:i+2] for i in range(0, 12, 2))
        output += " dst_mac="
        output += ":".join(self.dst_mac.hex()[i:i+2] for i in range(0, 12, 2))
        output += "\nsession_id=" + str(self.session_id)
        output += " byte_counter=" + str(self.byte_counter)
        if self.control_packets != []:
            output += "\nControl Packets:\n"
            for cp in self.control_packets:
                output += "\t" + str(cp)
        else:
            output += "\nPacket Data=" + self.data.hex()
        return output

    # length of packet data
    def __len__(self):
        return len(self.to_bytes()) - PACKET_HEADER_LEN

    def to_bytes(self):
        header = pack(">BB6s6sHHI",
                      self.version,
                      self.message_type,
                      self.src_mac,
                      self.dst_mac,
                      self.session_id,
                      self.client_type,
                      self.byte_counter)
        # if there's control packets, add them and return
        if self.control_packets != []:
            cp_bytes = b''.join([cp.to_bytes() for cp in self.control_packets])
            return header + cp_bytes
        # otherwise, just append data
        return header + self.data

    @classmethod
    def from_bytes(cls, data):
        packet = cls()
        (packet.version,
         packet.message_type,
         packet.src_mac,
         packet.dst_mac,
         packet.session_id,
         packet.client_type,
         packet.byte_counter) = unpack(">BB6s6sHHI", data[:PACKET_HEADER_LEN])

        # if there's nothing remaining, or no control packets, just return
        remaining = data[PACKET_HEADER_LEN:]
        if remaining == b'':
            return packet
        if remaining[:4] != CP_MAGIC:
            packet.data = remaining
            return packet

        while remaining != b'':
            remaining, cpacket = ControlPacket.from_bytes(remaining)
            packet.control_packets.append(cpacket)
        return packet

class MACTelnetProtocol(asyncio.Protocol):

    def __init__(self, mac, username, password, on_session_end):
        self.username = username
        self.password = password
        self.my_ip = None
        self.src_mac = uuid.getnode().to_bytes(6, "big")
        self.dst_mac = bytes.fromhex(mac.replace(":", ""))
        self.port = 20561
        self.session_id = secrets.randbits(16)
        self.transport = None

        self.unacked_packet = None
        self.acked_counter = 0
        self.send_counter = 0
        self.receive_counter = 0
        self.last_msg_time = time.time()

        self.w = elliptic_curves.WCurve()
        self.client_private = b''
        self.client_public = b''
        self.server_public = b''
        self.client_parity = -1
        self.server_parity = -1
        self.salt = b''

        self.old_tty = termios.tcgetattr(sys.stdin.fileno())
        self.on_session_end = on_session_end
        self.keepalive_task = asyncio.create_task(self.keepalive())

    def make_packet(self, message_type):
        packet = Packet()
        packet.message_type = message_type
        packet.src_mac = self.src_mac
        packet.dst_mac = self.dst_mac
        packet.session_id = self.session_id
        packet.byte_counter = self.send_counter
        return packet

    async def keepalive(self):
        while True:
            if time.time() > self.last_msg_time + 10:
                self.send_ack(None)
                self.last_msg_time = time.time()
            elif self.on_session_end.done():
                return
            else:
                await asyncio.sleep(0.001)

    def send(self, packet):
        # resend last packet if not acked
        if self.unacked_packet is not None and (self.acked_counter < self.send_counter or
                                                self.acked_counter + self.send_counter > 65535):
            self.transport.sendto(self.unacked_packet.to_bytes(),
                                  ("255.255.255.255", self.port))

        self.send_counter += len(packet)

        if self.send_counter > 65535:
            self.send_counter -= 65536

        self.transport.sendto(packet.to_bytes(),
                              ("255.255.255.255", self.port))
        self.unacked_packet = packet

    def send_ack(self, packet):
        ack = self.make_packet(SYS_ACKNOWLEDGE)
        if packet is not None:
            ack.byte_counter = packet.byte_counter + len(packet)
        else:
            # for keep alives:
            ack.byte_counter = self.receive_counter
        self.transport.sendto(ack.to_bytes(), ("255.255.255.255", self.port))

    def gen_confirmation_code(self):
        validator = self.w.gen_password_validator_priv(self.username, self.password, self.salt)
        validator_point = self.w.redp1(self.w.gen_public_key(validator)[0], 1)
        server_public_point = self.w.lift_x(int.from_bytes(self.server_public, "big"),
                                            self.server_parity)
        server_public_point += validator_point
        pubkeys_hashed = encryption.get_sha2_digest(self.client_public + self.server_public)
        vh = int.from_bytes(validator, "big") * int.from_bytes(pubkeys_hashed, "big")
        vh += int.from_bytes(self.client_private, "big")
        vh = self.w.finite_field_value(vh)
        pt = vh * server_public_point
        z_input, _ = self.w.to_montgomery(pt)
        return encryption.get_sha2_digest(pubkeys_hashed + z_input)

    def handle_control_packet(self, packet):
        # assume len(packet.control_packets) > 1
        if packet.control_packets[0].packet_type == CP_ENCRYPTION_KEY:
            self.server_public = packet.control_packets[0].data[:0x20]
            self.server_parity = packet.control_packets[0].data[0x20]
            self.salt = packet.control_packets[0].data[0x21:]

            if len(self.salt) != 16:
                # server error retrieving user, exit
                print("error: user not registered on server")
                self.on_session_end.set_result(True)
                return

            confirmation_code = self.gen_confirmation_code()

            confirmation = self.make_packet(SYS_DATA)
            confirmation.control_packets.append(
                ControlPacket(CP_PASSWORD, confirmation_code))
            confirmation.control_packets.append(
                ControlPacket(CP_USERNAME, self.username.encode()))

            term_type = os.getenv("TERM").encode()
            term_size = os.get_terminal_size()
            term_width = term_size[0].to_bytes(2, "little")
            term_height = term_size[1].to_bytes(2, "little")

            confirmation.control_packets.append(
                ControlPacket(CP_TERMINAL_TYPE, term_type))
            confirmation.control_packets.append(
                ControlPacket(CP_TERMINAL_WIDTH, term_width))
            confirmation.control_packets.append(
                ControlPacket(CP_TERMINAL_HEIGHT, term_height))
            self.send(confirmation)

        elif packet.control_packets[0].packet_type == CP_END_AUTHENTICATION:
            # not exactly "logged in" because auth can fail,
            # but we receieve auth failure as terminal data so we set it up here
            tty.setraw(sys.stdin)
            # helps with reliability to reset window after auth
            loop = asyncio.get_running_loop()
            loop.call_later(1, handle_sigwinch, self)

    # asyncio.Protocol methods
    def connection_made(self, transport):
        self.transport = transport
        self.send(self.make_packet(SYS_START_SESSION))

    def datagram_received(self, data, addr):
        if self.my_ip is None: # assume first packet is from me
            self.my_ip = addr[0]
            return
        if self.my_ip == addr[0]: # and ignore all future packets from myself
            return

        self.last_msg_time = time.time()
        packet = Packet.from_bytes(data)

        if packet.message_type == SYS_START_SESSION:
            print("error: client recieved SYS_START_SESSION")
        elif packet.message_type == SYS_DATA:
            self.send_ack(packet)

            if packet.byte_counter + len(packet) > self.receive_counter or \
              self.receive_counter + len(packet) > 65535:
                # new data, set receive_counter
                self.receive_counter += len(packet)
            else:
                # repeat packet, don't handle
                return

            if packet.control_packets != []:
                self.handle_control_packet(packet)
            else:
                # terminal data, print to stdout
                sys.stdout.buffer.write(packet.data)
                sys.stdout.flush()

        elif packet.message_type == SYS_ACKNOWLEDGE:
            if self.acked_counter <= packet.byte_counter or \
              self.acked_counter + packet.byte_counter > 65535:
                self.acked_counter = packet.byte_counter

            # initial ack from server, start handshake
            if self.client_private == b'':
                self.client_private = secrets.token_bytes(32)
                self.client_public, self.client_parity = self.w.gen_public_key(self.client_private)
                key_data = self.username.encode('utf-8') + b'\x00'
                key_data += self.client_public
                key_data += int(self.client_parity).to_bytes(1, "big")

                pubkey_packet = self.make_packet(SYS_DATA)
                pubkey_packet.control_packets = [
                    ControlPacket(CP_BEGIN_AUTHENICATION),
                    ControlPacket(CP_ENCRYPTION_KEY, key_data)
                    ]
                self.send(pubkey_packet)

        elif packet.message_type == SYS_END_SESSION:
            self.send_ack(packet)
            self.send(self.make_packet(SYS_END_SESSION))
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self.old_tty)
            self.on_session_end.set_result(True)

        else:
            print("error: unknown message type")

def handle_sigwinch(mactelnet):
    packet = mactelnet.make_packet(SYS_DATA)
    term_size = os.get_terminal_size()
    term_width = term_size[0].to_bytes(2, "little")
    term_height = term_size[1].to_bytes(2, "little")

    packet.control_packets.append(
        ControlPacket(CP_TERMINAL_WIDTH, term_width))
    packet.control_packets.append(
        ControlPacket(CP_TERMINAL_HEIGHT, term_height))

    mactelnet.send(packet)

def send_raw_byte(mactelnet):
    char = sys.stdin.buffer.raw.read(1)
    packet = mactelnet.make_packet(SYS_DATA)
    packet.data = char
    mactelnet.send(packet)

async def main(mac: str = "00:00:00:00:00:00", username: str = "admin", password: str = ""):
    loop = asyncio.get_running_loop()

    on_session_end = loop.create_future()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: MACTelnetProtocol(mac=mac,
                                  username=username,
                                  password=password,
                                  on_session_end=on_session_end),
        allow_broadcast=True, local_addr=('0.0.0.0', 20561))

    loop.add_reader(sys.stdin, lambda: send_raw_byte(protocol))

    loop.add_signal_handler(
        getattr(signal, "SIGWINCH"),
        lambda: handle_sigwinch(protocol))

    try:
        await asyncio.gather(
            on_session_end,
            protocol.keepalive_task
            )
    finally:
        transport.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MAC Telnet Client')
    parser.add_argument('mac')
    parser.add_argument('-u', '--username')
    parser.add_argument('-p', '--password')

    args = parser.parse_args()

    username = args.username if args.username is not None else input("Username: ")
    password = args.password if args.password is not None else getpass.getpass("Password: ")

    asyncio.run(main(args.mac, username, password))
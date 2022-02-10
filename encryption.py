from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256

def gen_stream_keys(server: bool, z: bytes):
    #### compute receive and send keys ####
    magic2 = b"On the client side, this is the send key; on the server side, it is the receive key."
    magic3 = b"On the client side, this is the receive key; on the server side, it is the send key."

    if server:
        txEnc = z + b'\00' * 40 + magic3 + b'\xf2' * 40
        rxEnc = z + b'\00' * 40 + magic2 + b'\xf2' * 40
    else:
        txEnc = z + b'\00' * 40 + magic2 + b'\xf2' * 40
        rxEnc = z + b'\00' * 40 + magic3 + b'\xf2' * 40

    # rx is receive seed, tx is send ("to") seed
    sha = SHA1.new()
    sha.update(rxEnc)
    rxEnc = sha.digest()[:16]
    sha = SHA1.new()
    sha.update(txEnc)
    txEnc = sha.digest()[:16]
    # parse keys from HKDF output
    send_key = HKDF(txEnc)
    send_aes_key = send_key[:0x10]
    send_hmac_key = send_key[0x10:]
    receive_key = HKDF(rxEnc)
    receive_aes_key = receive_key[:0x10]
    receive_hmac_key = receive_key[0x10:]
    return send_aes_key, receive_aes_key, send_hmac_key, receive_hmac_key

def HKDF(message: bytes):
    h = HMAC.new(b'\x00' * 0x40, b'', SHA1)
    h.update(message)
    h1 = h.digest()
    h2 = b''
    res = b''
    for i in range(0, 2):
        h = HMAC.new(h1, b'', SHA1)
        h.update(h2)
        h.update((i + 1).to_bytes(1, "big"))
        h2 = h.digest()
        res += h2
    return res[:0x24]

def get_sha2_digest(input: bytes):
    sha = SHA256.new()
    sha.update(input)
    return sha.digest()
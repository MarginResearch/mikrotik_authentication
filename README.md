# MikroTik Authentication POCs

This repo contains utilities and proofs of concept (POCs) demonstrating MikroTik routers' cryptographic protocols, specifically the implementation of Elliptic Curve Secure Remote Password (EC-SRP5) employed in software versions 6.54.1+. MikroTik's RouterOS operating system leverages this protocol for authentication in its proprietary Winbox (TCP port 8291) and MAC Telnet (UDP broadcast on port 20561) services. The following README contains an overview of the provided utilities and programs. See [Margin Research’s blog post](https://margin.re/blog/MikroTik-authentication-revealed.aspx) for additional information and graphics. 

## Quick Start Guide 
1. Clone the repo
2. Install the following `pip` dependencies: `pip install ecdsa pycryptodome`
3. Run the program of your choice against a MikroTik device on your network

### Winbox 
Simply execute `python3 winbox_server.py -d <path to user.dat> -a <address>` to start a Winbox server. The repo includes an example `user.dat` file for the credentials `admin : ` (password is blank). Connect to the server on port 8291 using the Winbox client program or the Winbox.exe program itself. The multi-threaded server authenticates and prints decrypted messages received from any of the clients. The program also contains a single "mock" response to the first default Winbox.exe request to demonstrate successful encryption and decryption. 

Execute `python3 winbox.py -t <target address> -u <username> [-p <password>]` to demonstrate Winbox client functionality, or leverage the Winbox API to send custom messages to the server. The default password, if omitted, is blank. Below is an example of the client API.

```python
import winbox

w = winbox.Winbox('127.0.0.1')
w.auth('admin', '')
msg = b'M2\x05\x00\xff\x01\x06\x00\xff\t\x01\x07\x00\xff\t\x07\x01\x00\xff\x88\x02\x00\r\x00\x00\x00\x04\x00\x00\x00\x02\x00\xff\x88\x02\x00\x00\x00\x00\x00\x0b\x00\x00\x00'
resp = w.send(msg)
print("Received response: ")
print(resp)
```

### MAC Telnet 
The MAC Telnet program only functions in client mode and requires a MikroTik host (version 6.45.1+) running on the same subnet to demonstrate functionality. Run `python3 mactelnet.py <mac address> [-u <username> -p <password>]` to authenticate and create a remote RouterOS terminal within the target host. 

## Elliptic Curves Utilities 
`elliptic_curves.py` contains cryptographic functions for authentication. It exposes the `WCurve` class which performs elliptic curve calculations and conversions between Montgomery and Weierstrass curves as well as between affine and weighted projective space. [Margin Research’s blog post](https://margin.re/blog/MikroTik-authentication-revealed.aspx) contains a high-level overview of the EC-SRP5 implementation, and this [old, unfinished IEEE submission draft](https://web.archive.org/web/20131228182531/http://grouper.ieee.org/groups/1363/passwdPK/submissions/p1363ecsrp.pdf) is a nearly identical protocol to what is implemented. Similarities to this draft submission are highlighted below:

1. `gen_public_key` accepts a private key and returns a public key. This is equivalent to ECPEPKGP-SRP-A. *Note: the private key is multiplied over the Weierstrass curve, but the public key returned is the converted Montgomery form x coordinate*
2. `lift_x` plots a provided x coordinate on the Weierstrass curve in affine form. This makes up a component of ECEDP and is used in public key generation
3. `redp1` is named according to old MikroTik symbols. This incorporates elements of two functions: it increments the x coordinate until `lift_x` returns a valid point, similar to ECEDP, and it hashes the x coordinate before plotting, similar to steps in ECPESVDP-SRP-A and ECPEPKGP-SRP-B for computing the pseudo-random point `e`

## Encryption Utilities 
`encryption.py` imports required cryptographic classes and calculates encryption and authentication keys.  RouterOS employs Mac-then-Encrypt for all messages and uses HMAC and AES-CBC. It also uses unique send and receive ciphers. Both Winbox and MAC Telnet POCs demonstrate successful encryption and decryption. *Note: the AES-CBC implementation uses a modified padding that is similar to PKCS-7. Instead of padding `n` bytes with character `n`, the padding is `n` bytes of character `n-1`*

It is worth mentioning that Winbox fragments the source message - after computing the authentication hash and encrypting - if longer than `0xff`. Both Winbox client and server scripts reassemble fragmented messages. 
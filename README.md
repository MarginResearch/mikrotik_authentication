# Mikrotik Authentication POCs

This repo contains utilties and proofs of concepts (POCs) demonstrating Mikrotik routers' crytpographic protocols, specifically the implementation of Elliptic Curve Secure Remote Password (EC-SRP5) employed in software versions 6.54.1+. Mikrotik's RouterOS operating system leverages this protocol for authentication in its proprietary Winbox (TCP port 8291) and MAC-Telnet (UDP port 5150) services. The following read-me contains an overview of the provided utilties and programs. [Margin Reserach's blog](https://margin.re/blog/mikrotik-authentication-revealed.aspx) has additional information. 

## Quick Start Guide 
1. Clone the repo
2. Install the following `pip` dependencies: `pip install ecdsa pycryptodome`
3. Run the program of your choice

### Winbox 
Simply execute `python3 winbox_server.py -d <path to user.dat> -a <address>` to start a Winbox server. The repo includes an example `user.dat` file for the credentials `admin : ` (password is blank). Connect to the server on port 8291 using the Winbox client program or the Winbox.exe program itself. The multi-threaded server authenticates up to five clients and prints decrypted messages received from any of the clients. The program also contains a single "mock" response to the first default Winbox.exe request to demonstrate successful encryption and decryption. 

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

### MAC-Telnet 
The MAC-Telnet program only functions in client mode and requires a Mikrotik host (version 6.45.1+) to demonstrate functionality. Run `python3 mactelnet.py <host>####` to authenticate and create a remote RouterOS terminal within the target host. 

## Elliptic Curves Utilities 
`elliptic_curves.py` contains cryptographic functions for authentication. It exposes the `WCurve` class which performs elliptic curve calculations and conversions between Montgomery and Weierstrass curves as well as between affine and weighted projective space. The [Margin Reserach's blog](https://margin.re/blog/mikrotik-authentication-revealed.aspx) contains a high-level overview of the EC-SRP5 implementation. 

## Encryption Utilities 
`encryption.py` imports required cryptographic classes and calculates encryption and authentication keys.  RouterOS employs Mac-then-Encrypt for all messages using HMAC and AES-CBC. It also uses unique send and receive ciphers. Both Winbox and MacTelnet demonstrate successful encryption and decryption in their POCs. 
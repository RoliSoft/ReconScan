#!/usr/bin/env python3
import re
import socket
import random
import asyncio
import difflib
from os import stat_result
from xeger import Xeger
from thefuzz import process

probes = {'UDP': {}, 'TCP': {}}
payloads = {'UDP': {}, 'TCP': {}}

with open('/usr/local/Cellar/nmap/7.92/share/nmap/nmap-service-probes', 'r') as f:
    lines = f.readlines()
    
    current = None
    for line in lines:
        line = line.strip()
        lowline = line.lower()

        if not line:
            continue

        if lowline.startswith('probe '):
            (probe_type, proto, name, payload) = line.split(' ', 3)
            payload = payload[2:-1].encode('utf-8').decode('unicode_escape')
            probes[proto][name] = payload
            current = (proto, name)

        elif lowline.startswith('match ') or lowline.startswith('softmatch '):
            if not current:
                continue

            (action, name, regex) = (line.split(' ', 2))

            rgxsep = regex[1]
            rgxend = regex[2:].find(rgxsep) + 2

            regex = regex[2:rgxend]

            if current[1] not in payloads[current[0]]:
                payloads[current[0]][current[1]] = []

            payloads[current[0]][current[1]].append(regex)


def get_match(payload, probes):
    plen = min(len(payload), 50)
    processed = [i[0:plen] for i in list(probes['UDP'].values())]
    closest = difflib.get_close_matches(payload[0:plen], processed, 1, cutoff=0)

    if not closest:
        closest, score = process.extractOne(payload[0:plen], processed)
    else:
        closest = closest[0]

    for name, probe in probes['UDP'].items():
        if probe[0:plen] == closest:
            return (name, probe, payloads['UDP'][name])

    return None

def gen_random(payloads):
    random.shuffle(payloads)
    payload = None
    x = Xeger(limit=1)

    for regex in payloads:
        #payload = rstr.xeger(regex)
        #payload = exrex.getone(regex)
        payload = x.xeger(regex)

        match = re.match(regex, payload)
        if match:
            return payload

    # relax matcher

    for regex in payloads:
        payload = x.xeger(regex)

        match = re.match(regex, payload, re.IGNORECASE | re.MULTILINE)
        if match:
            return payload

    return payload

def get_response(message):
    match = get_match(message.decode('unicode_escape'), probes)
    if not match:
        print('could not match to any probe')
        return None

    reply = gen_random(match[2])
    if not reply:
        print('could not generate payload')
        return None

    print("replying with match from {}".format(match[0]))

    return reply.encode('unicode_escape')


class HoneypotServerTCP(asyncio.Protocol):
    def connection_made(self, transport):
        self.peer = transport.get_extra_info('peername')
        self.transport = transport

    def data_received(self, data):
        print('data received from {}: {}'.format(self.peer[0], data))

        reply = get_response(data)
        if reply is not None:
            self.transport.write(reply)

        self.transport.close()

    def error_received(self, exc):
        print("exception thrown: %s" % exc)


class HoneypotServerUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        print('data received from {}: {}'.format(addr[0], data))
        
        reply = get_response(data)
        if reply is not None:
            self.transport.sendto(reply, addr)

    def error_received(self, exc):
        print("exception thrown: %s" % exc)

loop = asyncio.get_event_loop()

for i in range(1, 1024):
    try:
        tcp_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)
        tcp_socket.bind(('::', i))
        server = loop.run_until_complete(loop.create_server(HoneypotServerTCP, sock=tcp_socket))
        loop.create_task(server.serve_forever())
    except:
        print(f'failed to bind to TCP port {i}')

    try:
        udp_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        udp_socket.bind(('::', i))
        transport, protocol = loop.run_until_complete(loop.create_datagram_endpoint(HoneypotServerUDP, sock=udp_socket))
    except:
        print(f'failed to bind to UDP port {i}')

print('TCP and UDP servers up and listening')

try:
    loop.run_forever()
except:
    pass

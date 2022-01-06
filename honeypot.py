#!/usr/bin/env python3
import re
import select
import rstr
from os import stat_result
import exrex
from xeger import Xeger
import difflib
from thefuzz import process
import socket
import random

# read probes from  /usr/local/Cellar/nmap/7.92/share/nmap/nmap-service-probes
# match closest incoming payload difflib.get_close_matches('Hello', words)
# generate random response exrex.getone or rstr.xeger

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
        (closest, score) = process.extractOne(payload[0:plen], processed)
    else:
        closest = closest[0]

    for (name, probe) in probes['UDP'].items():
        if probe[0:plen] == closest:
            return (name, probe, payloads['UDP'][name])

    return None

def gen_random(payloads):
    #regex = random.choice(payloads)
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

#print(gen_random(payloads['UDP']['SIPOptions']))


sockets = {}
poller = select.poll()

for i in range(20, 1024):
    try:
        tcp_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)
        tcp_socket.bind(('::', i))
        tcp_socket.listen()
        sockets[tcp_socket.fileno()] = tcp_socket
        poller.register(tcp_socket, select.POLLIN)
    except:
        print('failed to bind to TCP port {}'.format(i))

    try:
        udp_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        udp_socket.bind(('::', i))
        sockets[udp_socket.fileno()] = udp_socket
        poller.register(udp_socket, select.POLLIN)
    except:
        print('failed to bind to UDP port {}'.format(i))

print("TCP and UDP servers up and listening")

while(True):
    #readable, writable, exceptional = select.select(sockets, [], sockets)
    #for sock in readable:

    fds = poller.poll(10000)
    for fd, Event in fds:
        sock = sockets[fd]
        try:
            if sock.type == socket.SOCK_STREAM:

                # TCP

                conn, address = sock.accept()
                message = conn.recv(10240)

                print("\nincoming from {}: {}".format(address[0], message))

                match = get_match(message.decode('unicode_escape'), probes)
                if not match:
                    print('Could not match to any probe')
                    continue

                reply = gen_random(match[2])
                if not reply:
                    print('Could not generate payload')
                    continue

                print("replying with match from {}".format(match[0]))

                conn.sendall(reply.encode('unicode_escape'))
                conn.close()
            
            elif sock.type == socket.SOCK_DGRAM:

                # UDP

                message, address = sock.recvfrom(10240)

                print("\nincoming from {}: {}".format(address[0], message))

                match = get_match(message.decode('unicode_escape'), probes)
                if not match:
                    print('Could not match to any probe')
                    continue

                reply = gen_random(match[2])
                if not reply:
                    print('Could not generate payload')
                    continue

                print("replying with match from {}".format(match[0]))

                sock.sendto(reply.encode('unicode_escape'), address)

        except BaseException as e:
            print('error: ' + str(e))
            continue


#!/usr/bin/env python3
#
#    Universal honeypot server for scanner testing purposes.
#    Copyright (C) 2021 RoliSoft <root@rolisoft.net>
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU Affero General Public License, either version 3 of the License, or
#    (at your option) any later version.
#

import os
import re
import yaml
import array
import socket
import random
import asyncio
import difflib
import argparse
from xeger import Xeger
from thefuzz import process
from lib.colors import debug, info, warn, error, fail



class Honeypot:
	verbose  = 0
	probes   = None
	payloads = None

	def load_probes(self):
		if not os.path.exists('data/service-probes'):
			error('Could not find {bgreen}data/service-probes{rst}.')
			return False

		self.probes   = {'UDP': {}, 'TCP': {}}
		self.payloads = {'UDP': {}, 'TCP': {}}

		with open('data/service-probes', 'r') as f:
			lines = f.readlines()
			
			current = None
			for line in lines:
				line = line.strip()
				lowline = line.lower()

				if not line:
					continue

				if lowline.startswith('probe '):
					probe_type, proto, name, payload = line.split(' ', 3)
					payload = payload[2:-1].encode('utf-8').decode('unicode_escape')
					self.probes[proto][name] = payload
					current = (proto, name)

				elif lowline.startswith('match ') or lowline.startswith('softmatch '):
					if not current:
						continue

					action, name, regex = line.split(' ', 2)

					# check what separator is being used for the regex
					# and extract the regex itself

					rgxsep = regex[1]
					rgxend = regex[2:].find(rgxsep) + 2
					regex  = regex[2:rgxend]

					if current[1] not in self.payloads[current[0]]:
						self.payloads[current[0]][current[1]] = []

					self.payloads[current[0]][current[1]].append(regex)

		if self.verbose >= 1:
			tcp_probes = len(self.probes['TCP'])
			udp_probes = len(self.probes['UDP'])
			debug('Loaded {bgreen}{tcp_probes}{rst} TCP and {bgreen}{udp_probes}{rst} UDP probes.')
			
		return len(self.probes['UDP']) > 0 and len(self.probes['TCP']) > 0


	def load_ports(self):
		if not os.path.exists('data/port-popularity'):
			error('Could not find {bgreen}data/port-popularity{rst}.')
			return False

		self.port_popularity = {}

		with open('data/port-popularity', 'r') as f:
			data = yaml.load(f, Loader=yaml.BaseLoader)
			self.port_popularity = {'TCP': data[0]['TCP'], 'UDP': data[1]['UDP']}


	def parse_range(self, interval):
		numbers = []
		ranges = interval.split(',')
		
		for current in ranges:
			interim = current.split('-')

			if len(interim) == 1:
				numbers.append(int(interim[0]))
			else:
				numbers.extend(list(range(int(interim[0]), int(interim[1]) + 1)))

		return numbers


	def set_ports(self, tcp_range, udp_range, top_tcp, top_udp):
		if top_tcp or top_udp:
			self.load_ports()

		if not top_tcp:
			self.tcp_ports = self.parse_range(tcp_range)
		else:
			self.tcp_ports = self.port_popularity['TCP'][:top_tcp]

		if not top_udp:
			self.udp_ports = self.parse_range(udp_range)
		else:
			self.udp_ports = self.port_popularity['UDP'][:top_udp]


	def map_to_probe(self, payload, proto):
		plen = min(len(payload), 50)
		processed = [i[0:plen] for i in list(self.probes[proto].values())]
		closest = difflib.get_close_matches(payload[0:plen], processed, 1, cutoff=0)

		if not closest:
			closest, score = process.extractOne(payload[0:plen], processed)
		else:
			closest = closest[0]

		for name, probe in self.probes[proto].items():
			if probe[0:plen] == closest:
				return name, probe, self.payloads[proto][name]

		return None


	def generate_service_reply(self, payloads):
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


	def handle_message(self, message, proto):
		match = self.map_to_probe(message.decode('unicode_escape'), proto)
		if not match:
			return None, None, 'Could not match to any probe.'

		reply = self.generate_service_reply(match[2])
		if not reply:
			return None, None, 'Could not generate payload.'

		#ret = reply.encode('unicode_escape')
		ret = array.array('B', [x for x in map(ord,reply)]).tobytes()
		return match[0], ret, None


	def serve(self):
		loop = asyncio.get_event_loop()

		tcp_success = 0
		for port in self.tcp_ports:
			if self.verbose >= 2:
				debug('Starting listener for TCP port {byellow}{port}{rst}...')

			try:
				tcp_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)
				tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				tcp_socket.bind(('::', int(port)))

				loop_server = loop.run_until_complete(
					loop.create_server(
						lambda: HoneypotServerTCP(self),
						sock=tcp_socket))
				loop.create_task(loop_server.serve_forever())

				tcp_success += 1
			except:
				error('Failed to bind to TCP port {port}.')

		info('Started listening on {byellow}{tcp_success}{rst} TCP ports.')

		udp_success = 0
		for port in self.udp_ports:
			if self.verbose >= 3:
				debug('Starting listener for UDP port {byellow}{port}{rst}...')

			try:
				udp_socket = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
				udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				udp_socket.bind(('::', int(port)))

				transport, protocol = loop.run_until_complete(
					loop.create_datagram_endpoint(
						lambda: HoneypotServerUDP(self),
						sock=udp_socket))
				
				udp_success += 1
			except:
				error('Failed to bind to UDP port {port}.')

		info('Started listening on {byellow}{udp_success}{rst} UDP ports.')

		try:
			loop.run_forever()
		except:
			pass


class HoneypotServerTCP(asyncio.Protocol):
	def __init__(self, server):
		self.server = server
		self.truncation_length = 60
		self.truncation_marker = ' [...]'.encode('ascii')
		super().__init__()

	def connection_made(self, transport):
		self.peer = transport.get_extra_info('peername')
		self.transport = transport

	def data_received(self, data):
		lport = self.transport.get_extra_info('sockname')[1]

		if self.server.verbose >= 1:
			debug('Data on {byellow}tcp:{lport}{rst} from {byellow}{self.peer[0]}{rst}: {bblue}{data}{rst}')

		proto, reply, error = self.server.handle_message(data, 'TCP')
		if reply is not None:
			if self.server.verbose >= 1:
				trunc = reply
				if self.server.verbose < 2 and len(trunc) > self.truncation_length:
					trunc = trunc[:60] + self.truncation_marker
				debug('Replying to {byellow}{self.peer[0]}{rst} with {bgreen}{proto}{rst}: {bblue}{trunc}{rst}')
			else:
				info('Data on {byellow}tcp:{lport}{rst} from {byellow}{self.peer[0]}{rst}, replying with {bgreen}{proto}{rst}.')

			self.transport.write(reply)
		else:
			if self.server.verbose >= 1:
				debug('Closing connection on {byellow}tcp:{lport}{rst} with {byellow}{self.peer[0]}{rst}: {bred}{error}{rst}')
			else:
				info('Refusing connection on {byellow}tcp:{lport}{rst} from {byellow}{self.peer[0]}{rst}: {bred}{error}{rst}')

		self.transport.close()

	def error_received(self, exc):
		lport = self.transport.get_extra_info('sockname')[1]
		error('Error on {byellow}tcp:{lport}{rst} from {byellow}tcp:{self.peer[0]}{rst}: {bred}{exc}{rst}')


class HoneypotServerUDP(asyncio.DatagramProtocol):
	def __init__(self, server):
		self.server = server
		self.truncation_length = 60
		self.truncation_marker = ' [...]'.encode('ascii')
		super().__init__()

	def connection_made(self, transport):
		self.transport = transport

	def datagram_received(self, data, addr):
		lport = self.transport.get_extra_info('sockname')[1]

		if self.server.verbose >= 1:
			debug('Data on {byellow}udp:{lport}{rst} from {byellow}{addr[0]}{rst}: {bblue}{data}{rst}')
		
		proto, reply, error = self.server.handle_message(data, 'UDP')
		if reply is not None:
			if self.server.verbose >= 1:
				trunc = reply
				if self.server.verbose < 2 and len(trunc) > self.truncation_length:
					trunc = trunc[:60] + self.truncation_marker
				debug('Replying to {byellow}{addr[0]}{rst} with {bgreen}{proto}{rst}: {bblue}{trunc}{rst}')
			else:
				info('Data on {byellow}udp:{lport}{rst} from {byellow}{addr[0]}{rst}, replying with {bgreen}{proto}{rst}.')

			self.transport.sendto(reply, addr)
		else:
			if self.server.verbose >= 1:
				debug('Closing connection on {byellow}udp:{lport}{rst} with {byellow}{addr[0]}{rst}: {bred}{error}{rst}')
			else:
				info('Refusing connection on {byellow}udp:{lport}{rst} from {byellow}{addr[0]}{rst}: {bred}{error}{rst}')

	def error_received(self, exc):
		lport = self.transport.get_extra_info('sockname')[1]
		error('Error on {byellow}udp:{lport}{rst}: {bred}{exc}{rst}')


if __name__ == '__main__':
	s = Honeypot()

	parser = argparse.ArgumentParser(description='Universal honeypot server for scanner testing purposes.')
	parser.add_argument('-p', '--ports', action='store', default='1-10000', help='list of TCP ports to listen on; can be comma-separated numbers or ranges (e.g. 80,443-8443,9000-10000)')
	parser.add_argument('--top-ports', type=int, action='store', help='use the specified number of most popular TCP ports instead of port ranges')
	parser.add_argument('-u', '--udp-ports', action='store', default='1-10000', help='list of UDP ports to listen on; same format as TCP ports')
	parser.add_argument('--top-udp-ports', type=int, action='store', help='use the specified number of most popular UDP ports instead of port ranges')
	parser.add_argument('-v', '--verbose', action='count', help='enable verbose output, repeat for more verbosity')
	parser.error = lambda x: fail(x[0].upper() + x[1:])
	args = parser.parse_args()

	s.verbose  = args.verbose if args.verbose is not None else 0

	s.load_probes()
	s.set_ports(args.ports, args.udp_ports, args.top_ports, args.top_udp_ports)
	s.serve()

#!/usr/bin/env python3
#
#    Network reconnaissance tool for service enumeration.
#    Copyright (C) 2017 RoliSoft <root@rolisoft.net>
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import os
import sys
import csv
import atexit
import string
import shutil
import argparse
import threading
import subprocess
import multiprocessing
from libnmap.parser import NmapParser
from colorama import init, Fore, Back, Style

init()

class scanner:
	verbose     = 0
	dryrun      = False
	deepscan    = False
	bruteforce  = True
	outdir      = ''
	nmapparams  = ''
	hydraparams = ''
	parallel    = False
	hadsmb      = False
	srvname     = ''

	# region Colors

	def e(self, *args, frame_index=1, **kvargs):
		frame = sys._getframe(frame_index)

		vals = {}

		vals.update(frame.f_globals)
		vals.update(frame.f_locals)
		vals.update(kvargs)

		return string.Formatter().vformat(' '.join(args), args, vals)


	def cprint(self, *args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
		frame = sys._getframe(frame_index)

		vals = {
			'bgreen':  Fore.GREEN  + Style.BRIGHT,
			'bred':    Fore.RED    + Style.BRIGHT,
			'bblue':   Fore.BLUE   + Style.BRIGHT,
			'byellow': Fore.YELLOW + Style.BRIGHT,

			'green':  Fore.GREEN,
			'red':    Fore.RED,
			'blue':   Fore.BLUE,
			'yellow': Fore.YELLOW,

			'bright': Style.BRIGHT,
			'srst':   Style.NORMAL,
			'crst':   Fore.RESET,
			'rst':    Style.NORMAL + Fore.RESET
		}

		vals.update(frame.f_globals)
		vals.update(frame.f_locals)
		vals.update(kvargs)

		unfmt = ''
		if char is not None:
			unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + sep
		unfmt += sep.join(args)

		fmted = unfmt

		for attempt in range(10):
			try:
				fmted = string.Formatter().vformat(unfmt, args, vals)
				break
			except KeyError as err:
				key = err.args[0]
				unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

		print(fmted, sep=sep, end=end, file=file)


	def debug(self, *args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, **kvargs):
		if self.verbose >= 1:
			self.cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)


	def info(self, *args, sep=' ', end='\n', file=sys.stdout, **kvargs):
		self.cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)


	def warn(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
		self.cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)


	def error(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
		self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)


	def fail(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
		self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
		exit(-1)


	# endregion

	# region Process Management

	def dump_pipe(self, stream, stop_event=None, tag='?', color=Fore.BLUE):
		while stream.readable() and (stop_event is not None and not stop_event.is_set()):
			line = stream.readline().decode('utf-8').rstrip()

			if len(line) != 0:
				self.debug(color + '[' + Style.BRIGHT + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)


	def run_cmd(self, cmd, tag='?', redirect=None):
		if redirect is None:
			redirect = self.verbose >= 2

		self.info(('Skipping' if self.dryrun else 'Running') + ' task {bgreen}{tag}{rst}' + (' with {bblue}{cmd}{rst}' if self.verbose >= 1 else '...'))

		if self.dryrun:
			return True

		proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE if redirect else subprocess.DEVNULL, stderr=subprocess.PIPE if redirect else subprocess.DEVNULL)

		if redirect:
			thdout = threading.Event()
			thderr = threading.Event()

			threading.Thread(target=self.dump_pipe, args=(proc.stdout, thdout, tag)).start()
			threading.Thread(target=self.dump_pipe, args=(proc.stderr, thderr, tag, Fore.RED)).start()

		ret = proc.wait()

		if redirect:
			thdout.set()
			thderr.set()

		if ret != 0:
			self.error('Task {bred}{tag}{rst} returned non-zero exit code: {ret}')
		else:
			self.info('Task {bgreen}{tag}{rst} finished successfully.')

		return ret == 0


	def run_cmds(self, cmds):
		procs = []

		for cmd in cmds:
			proc = multiprocessing.Process(target=self.run_cmd, args=cmd)
			procs.append(proc)
			proc.start()

			if not self.parallel:
				if proc.is_alive():
					proc.join()

		if self.parallel:
			for proc in procs:
				if proc.is_alive():
					proc.join()


	# endregion

	# region Host Discovery

	def run_nmap(self, address):
		out = os.path.join(self.outdir, address + self.srvname)
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV -sC {self.nmapparams} -p- -oN "{out}/0_tcp_nmap.txt" -oX "{out}/0_tcp_nmap.xml" {address}'),
				'nmap-tcp'
			),
			(
				self.e('nmap -vv --reason -sV --version-intensity 0 -sC -sU {self.nmapparams} -oN "{out}/0_udp_nmap.txt" -oX "{out}/0_udp_nmap.xml" {address}'),
				'nmap-udp'
			)
		])

		nmap_svcs = []

		if os.path.exists(out + '/0_tcp_nmap.xml'):
			report = NmapParser.parse_fromfile(out + '/0_tcp_nmap.xml')
			nmap_svcs += report.hosts[0].services

		if os.path.exists(out + '/0_udp_nmap.xml'):
			report = NmapParser.parse_fromfile(out + '/0_udp_nmap.xml')
			nmap_svcs += report.hosts[0].services

		services  = []
		nmap_svcs = sorted(nmap_svcs, key=lambda s: s.port)

		for service in nmap_svcs:
			if 'open' not in service.state:
				continue

			self.info('Service {bgreen}{service.port}{rst}/{bgreen}{service.protocol}{rst} is {bgreen}{service.service}{rst}' + (' running {green}' + service.service_dict['product'] + '{crst}' if 'product' in service.service_dict else '') + (' version {green}' + service.service_dict['version'] + '{crst}' if 'version' in service.service_dict else ''))
			services.append((address, service.port * -1 if service.protocol == 'udp' else service.port, service.service))

		return services


	def run_amap(self, services, only_unidentified=True):
		out = os.path.join(self.outdir, services[0][0] + self.srvname)

		ports_tcp = ''
		ports_udp = ''

		for service in services:
			if only_unidentified and 'unknown' not in service[2]:
				continue

			if service[1] < 0:
				ports_udp += str(service[1] * -1) + ','
			else:
				ports_tcp += str(service[1]) + ','

		cmds = []

		if len(ports_tcp) != 0:
			ports = ports_tcp.rstrip(',')
			cmds.append(
				(
					self.e('amap -A -bqv -m -o "{out}/0_tcp_amap.txt" {services[0][0]} {ports}'),
					'amap-tcp'
				)
			)

		if len(ports_udp) != 0:
			ports = ports_udp.rstrip(',')
			cmds.append(
				(
					self.e('amap -A -bqvu -m -o "{out}/0_udp_amap.txt" {services[0][0]} {ports}'),
					'amap-udp'
				)
			)

		self.run_cmds(cmds)

		amap_svcs = []

		if os.path.exists(out + '/0_tcp_amap.txt'):
			with open(out + '/0_tcp_amap.txt') as file:
				reader = csv.reader(file, delimiter=':', quotechar='"', dialect=csv.unix_dialect)
				for row in reader:
					if len(row) > 5 and not row[0].startswith('#'):
						amap_svcs.append((row[0], int(row[1]) * -1 if row[2] == 'udp' else int(row[1]), row[5]))

		if os.path.exists(out + '/0_udp_amap.txt'):
			with open(out + '/0_udp_amap.txt') as file:
				reader = csv.reader(file, delimiter=':', quotechar='"', dialect=csv.unix_dialect)
				for row in reader:
					if len(row) > 5 and not row[0].startswith('#'):
						amap_svcs.append((row[0], int(row[1]) * -1 if row[2] == 'udp' else int(row[1]), row[5]))

		for i, val in enumerate(services):
			for amap_svc in amap_svcs:
				if services[i][0] == amap_svc[0] and services[i][1] == amap_svc[1] and ('unknown' in services[i][2] or not only_unidentified):
					services[i] = amap_svc

		return services


	# endregion

	# region Service Enumeration

	#
	#  HTTP(S)
	#  nmap, nikto, gobuster
	#

	def enum_http(self, address, port, service, basedir):
		scheme = 'https' if 'https' in service or 'ssl' in service else 'http'
		nikto_ssl = ' -ssl' if 'https' in service or 'ssl' in service else '' 

		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(http* or ssl*) and not (broadcast or dos or external or http-slowloris* or fuzzer)" -oN "{basedir}/{port}_http_nmap.txt" -oX "{basedir}/{port}_http_nmap.xml" {address}'),
				self.e('nmap-{port}')
			),
			(
				self.e('curl -i {scheme}://{address}:{port}/ -m 10 -o "{basedir}/{port}_http_index.html"'),
				self.e('curl-1-{port}')
			),
			(
				self.e('curl -i {scheme}://{address}:{port}/robots.txt -m 10 -o "{basedir}/{port}_http_robots.txt"'),
				self.e('curl-2-{port}')
			)
		])

		# wait for previous scan to finish, then:

		self.run_cmds([
			(
				self.e('gobuster -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 10 -u {scheme}://{address}:{port} -e -s "200,204,301,302,307,403,500" | tee "{basedir}/{port}_http_dirb.txt"'),
				self.e('gobuster-{port}')
			),
			(
				# -C all potentially slowing it down?
				self.e('nikto -h {scheme}://{address}:{port}{nikto_ssl} -o "{basedir}/{port}_http_nikto.txt"'),
				self.e('nikto-{port}')
			)
		])
		#try:
		#	with open(os.path.join('.', e('nikto_{address}.sh')), 'a') as file:
		#		file.writelines(e('nikto -h {scheme}://{address}:{port}{nikto_ssl} -o "{basedir}/{port}_http_nikto.txt"') + '\n') 
		#except:
		#	pass


	#
	#  SMTP
	#  nmap
	#

	def enum_smtp(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(smtp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_smtp_nmap.txt" -oX "{basedir}/{port}_smtp_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  POP3
	#  nmap
	#

	def enum_pop3(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(pop3*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_pop3_nmap.txt" -oX "{basedir}/{port}_pop3_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  IMAP
	#  nmap
	#

	def enum_imap(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(imap*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_imap_nmap.txt" -oX "{basedir}/{port}_imap_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  FTP
	#  nmap
	#

	def enum_ftp(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(ftp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_ftp_nmap.txt" -oX "{basedir}/{port}_ftp_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  SMB
	#  nmap, enum4linux, samrdump
	#

	def enum_smb(self, address, port, service, basedir):
		if self.hadsmb:
			return

		nmap_port = port
		if port == 139 or port == 445:
			nmap_port = '139,445'

		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {nmap_port} --script="(nbstat or smb*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 -oN "{basedir}/{port}_smb_nmap.txt" -oX "{basedir}/{port}_smb_nmap.xml" {address}'),
				self.e('nmap-{port}')
			),
			(
				self.e('enum4linux -a -M -l -d {address} | tee "{basedir}/{port}_smb_enum4linux.txt"'),
				self.e('enum4linux-{port}')
			),
			(
				self.e('python2 /usr/share/doc/python-impacket/examples/samrdump.py {address} {port}/SMB | tee "{basedir}/{port}_smb_samrdump.txt"'),
				self.e('samrdump-{port}')
			),
			(
				self.e('nbtscan -rvh {address} | tee "{basedir}/{port}_smb_nbtscan.txt"'),
				self.e('nbtscan-{port}')
			)
		])

		self.hadsmb = True


	#
	#  MSSQL
	#  nmap
	#

	def enum_mssql(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(ms-sql*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=mssql.instance-port={port},smsql.username-sa,mssql.password-sa -oN "{basedir}/{port}_mssql_nmap.txt" -oX "{basedir}/{port}_mssql_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  MySQL
	#  nmap
	#

	def enum_mysql(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(mysql*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_mysql_nmap.txt" -oX "{basedir}/{port}_mysql_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  Oracle
	#  nmap
	#

	def enum_oracle(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(oracle*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_oracle_nmap.txt" -oX "{basedir}/{port}_oracle_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  NFS
	#  nmap
	#

	def enum_nfs(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(rpcinfo or nfs*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_nfs_nmap.txt" -oX "{basedir}/{port}_nfs_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  SNMP
	#  nmap, onesixtyone, snmpwalk
	#

	def enum_snmp(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(snmp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_snmp_nmap.txt" -oX "{basedir}/{port}_snmp_nmap.xml" {address}'),
				self.e('nmap-{port}')
			),
			(
				self.e('onesixtyone -c data/community -dd -o "{basedir}/{port}_snmp_onesixtyone.txt" {address}'),
				self.e('onesixtyone-{port}')
			),
			(
				self.e('snmpwalk -c public -v 1 {address} | tee "{basedir}/{port}_snmp_snmpwalk.txt"'),
				self.e('snmpwalk-{port}')
			)
		])


	#
	#  DNS
	#  axfr with dig
	#

	def enum_dns(self, address, port, service, basedir):
		nmblookup = self.e("nmblookup -A {address} | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1")

		self.info('Running task {bgreen}nmblookup-{port}{rst}' + (' with {bblue}' + nmblookup + '{rst}' if self.verbose >= 1 else '...'))

		try:
			host = subprocess.check_output(nmblookup, shell=True, stderr=subprocess.DEVNULL).decode().strip()
		except subprocess.CalledProcessError:
			return

		self.run_cmds([
			(
				self.e('dig -p{port} @{host}.thinc.local thinc.local axfr > "{basedir}/{port}_dns_dig.txt"'),
				self.e('dig-{port}')
			)
		])


	#
	#  RDP
	#  nmap
	#

	def enum_rdp(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(rdp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_rdp_nmap.txt" -oX "{basedir}/{port}_rdp_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  VNC
	#  nmap
	#

	def enum_vnc(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV {self.nmapparams} -p {port} --script="(vnc* or realvnc*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 -oN "{basedir}/{port}_vnc_nmap.txt" -oX "{basedir}/{port}_vnc_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	#
	#  Unidentified service
	#  nmap
	#

	def enum_generic_tcp(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV -sC {self.nmapparams} -p {port} --script-args=unsafe=1 -oN "{basedir}/{port}_generic_tcp_nmap.txt" -oX "{basedir}/{port}_generic_tcp_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])

	def enum_generic_udp(self, address, port, service, basedir):
		self.run_cmds([
			(
				self.e('nmap -vv --reason -sV -sC {self.nmapparams} -sU -p {port} --script-args=unsafe=1 -oN "{basedir}/{port}_generic_udp_nmap.txt" -oX "{basedir}/{port}_generic_udp_nmap.xml" {address}'),
				self.e('nmap-{port}')
			)
		])


	# endregion

	def scan_service(self, address, port, service):
		if port < 0:
			is_udp = True
			port *= -1
		else:
			is_udp = False

		self.info('Scanning service {bgreen}{service}{rst} on port {bgreen}{port}{rst}/{bgreen}{proto}{rst}...', proto='udp' if is_udp else 'tcp')
		basedir = os.path.join(self.outdir, address + self.srvname)
		os.makedirs(basedir, exist_ok=True)

		if self.bruteforce:
			self.error('self.bruteforce-only mode is currently not available.')
			return

		if 'http' in service:
			self.enum_http(address, port, service, basedir)

		elif 'smtp' in service:
			self.enum_smtp(address, port, service, basedir)

		elif 'pop3' in service:
			self.enum_pop3(address, port, service, basedir)

		elif 'imap' in service:
			self.enum_imap(address, port, service, basedir)

		elif 'ftp' in service:
			self.enum_ftp(address, port, service, basedir)

		elif 'microsoft-ds' in service or 'netbios' in service:
			self.enum_smb(address, port, service, basedir)

		elif 'ms-sql' in service or 'msSql' in service:
			self.enum_mssql(address, port, service, basedir)

		elif 'mysql' in service:
			self.enum_mysql(address, port, service, basedir)

		elif 'oracle' in service:
			self.enum_oracle(address, port, service, basedir)

		elif 'nfs' in service or 'rpcbind' in service:
			self.enum_nfs(address, port, service, basedir)

		elif 'snmp' in service:
			self.enum_snmp(address, port, service, basedir)

		elif 'domain' in service or 'dns' in service:
			self.enum_dns(address, port, service, basedir)

		elif 'rdp' in service or 'ms-wbt-server' in service or 'ms-term-serv' in service:
			self.enum_rdp(address, port, service, basedir)

		elif 'vnc' in service:
			self.enum_vnc(address, port, service, basedir)

		elif not is_udp:
			self.warn('Service {byellow}{service}{rst} will be scanned generically.')

			self.enum_generic_tcp(address, port, service, basedir)

		else:
			if port <= 1024:
				self.warn('Service {byellow}{service}{rst} will be scanned generically.')
				
				self.enum_generic_udp(address, port, service, basedir)

			else:
				self.warn('Service {byellow}{service}{rst} will not be scanned generically.')

				with open(os.path.join(basedir, '0_untouched.txt'), 'a') as file:
					file.writelines(str(port) + '\t' + ('udp' if is_udp else 'tcp') + '\t' + service + '\n')


	def scan_host(self, address):
		self.info('Scanning host {byellow}{address}{rst}...')
		basedir = os.path.join(self.outdir, address + self.srvname)
		os.makedirs(basedir, exist_ok=True)

		services = self.run_nmap(address)

		if any('unknown' in s for s in services):
			services = self.run_amap(services)

		if self.deepscan:
			if len(services) != 0:
				self.info('Starting scan of services...')

			if os.path.exists(os.path.join(basedir, '0_untouched.txt')):
				os.unlink(os.path.join(basedir, '0_untouched.txt'))

			for service in services:
				self.scan_service(*service)


if __name__ == '__main__':
	s = scanner()

	if 'COLUMNS' not in os.environ:
		os.environ['COLUMNS'] = str(shutil.get_terminal_size((80, 20)).columns)

	parser = argparse.ArgumentParser(description='Network reconnaissance tool for enumerating the everliving fuck out of a host.')
	parser.add_argument('address', action='store', help='address of the host.')
	parser.add_argument('port', action='store', type=int, help='port of the service, if scanning only one port', nargs='?')
	parser.add_argument('service', action='store', help='type of the service, when port is specified', nargs='?')
	parser.add_argument('-b', '--bruteforce', action='store_true', help='only bruteforce credentials with hydra')
	parser.add_argument('-d', '--dry-run', action='store_true', help='does not invoke commands')
	parser.add_argument('-p', '--parallel', action='store_true', help='runs multiple commands in parallel, if set')
	parser.add_argument('-s', '--deep-scan', action='store_true', help='re-scans each service separately with broader settings')
	parser.add_argument('-v', '--verbose', action='count', help='enable verbose output, repeat for more verbosity')
	parser.add_argument('-n', '--name', action='store', help='name of the machine to append to the output name')
	parser.add_argument('-o', '--output', action='store', default='results', help='output directory for the results')
	parser.add_argument('--nmap', action='store', default='-Pn --min-rate=400 -T4 --script-timeout 10m', help='additional nmap arguments')
	parser.add_argument('--hydra', action='store', default='-L data/users -P data/passwords -t 16 -f', help='additional hydra arguments')
	parser.error = lambda s: s.fail(s[0].upper() + s[1:])
	args = parser.parse_args()

	s.bruteforce  = args.bruteforce
	s.dryrun      = args.dry_run
	s.parallel    = args.parallel
	s.deepscan    = args.deep_scan
	s.verbose     = args.verbose if args.verbose is not None else 0
	s.srvname     = '_' + args.name if args.name else ''
	s.outdir      = args.output
	s.nmapparams  = args.nmap
	s.hydraparams = args.hydra

	atexit.register(lambda: os.system('stty sane'))

	if args.port is not None:
		if args.service is None:
			s.fail('Service type is required when scanning only one port.')

		s.scan_service(args.address, args.port, args.service)
	else:
		s.scan_host(args.address)

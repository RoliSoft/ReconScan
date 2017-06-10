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

verbose     = 0
dryrun      = False
bruteforce  = True
outdir      = ''
nmapparams  = ''
hydraparams = ''
parallel    = False
hadsmb      = False
srvname     = ''

# region Colors


def e(*args, frame_index=1, **kvargs):
	frame = sys._getframe(frame_index)

	vals = {}

	vals.update(frame.f_globals)
	vals.update(frame.f_locals)
	vals.update(kvargs)

	return string.Formatter().vformat(' '.join(args), args, vals)


def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
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


def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, **kvargs):
	if verbose >= 1:
		cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)


def info(*args, sep=' ', end='\n', file=sys.stdout, **kvargs):
	cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)


def warn(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
	cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)


def error(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
	cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)


def fail(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
	cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
	exit(-1)


# endregion

# region Process Management


def dump_pipe(stream, stop_event=None, tag='?', color=Fore.BLUE):
	while stream.readable() and (stop_event is not None and not stop_event.is_set()):
		line = stream.readline().decode('utf-8').rstrip()

		if len(line) != 0:
			debug(color + '[' + Style.BRIGHT + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)


def run_cmd(cmd, tag='?', redirect=None):
	if redirect is None:
		redirect = verbose >= 2

	info(('Skipping' if dryrun else 'Running') + ' task {bgreen}{tag}{rst}' + (' with {bblue}{cmd}{rst}' if verbose >= 1 else '...'))

	if dryrun:
		return True

	proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE if redirect else subprocess.DEVNULL, stderr=subprocess.PIPE if redirect else subprocess.DEVNULL)

	if redirect:
		thdout = threading.Event()
		thderr = threading.Event()

		threading.Thread(target=dump_pipe, args=(proc.stdout, thdout, tag)).start()
		threading.Thread(target=dump_pipe, args=(proc.stderr, thderr, tag, Fore.RED)).start()

	ret = proc.wait()

	if redirect:
		thdout.set()
		thderr.set()

	if ret != 0:
		error('Task {bred}{tag}{rst} returned non-zero exit code: {ret}')
	else:
		info('Task {bgreen}{tag}{rst} finished successfully.')

	return ret == 0


def run_cmds(cmds):
	procs = []

	for cmd in cmds:
		proc = multiprocessing.Process(target=run_cmd, args=cmd)
		procs.append(proc)
		proc.start()

		if not parallel:
			if proc.is_alive():
				proc.join()

	if parallel:
		for proc in procs:
			if proc.is_alive():
				proc.join()


# endregion

# region Host Discovery


def run_nmap(address):
	out = os.path.join(outdir, address + srvname)
	run_cmds([
		(
			e('nmap -vv --reason -sV -sC {nmapparams} -p- -oN "{out}/0_tcp_nmap.txt" -oX "{out}/0_tcp_nmap.xml" {address}'),
			'nmap-tcp'
		),
		(
			e('nmap -vv --reason -sV --version-intensity 0 -sC -sU {nmapparams} -oN "{out}/0_udp_nmap.txt" -oX "{out}/0_udp_nmap.xml" {address}'),
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

		info('Service {bgreen}{service.port}{rst}/{bgreen}{service.protocol}{rst} is {bgreen}{service.service}{rst}' + (' running {green}' + service.service_dict['product'] + '{crst}' if 'product' in service.service_dict else '') + (' version {green}' + service.service_dict['version'] + '{crst}' if 'version' in service.service_dict else ''))
		services.append((address, service.port * -1 if service.protocol == 'udp' else service.port, service.service))

	return services


def run_amap(services, only_unidentified=True):
	out = os.path.join(outdir, services[0][0] + srvname)

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
				e('amap -A -bqv -m -o "{out}/0_tcp_amap.txt" {services[0][0]} {ports}'),
				'amap-tcp'
			)
		)

	if len(ports_udp) != 0:
		ports = ports_udp.rstrip(',')
		cmds.append(
			(
				e('amap -A -bqvu -m -o "{out}/0_udp_amap.txt" {services[0][0]} {ports}'),
				'amap-udp'
			)
		)

	run_cmds(cmds)

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

def enum_http(address, port, service, basedir):
	scheme = 'https' if 'https' in service or 'ssl' in service else 'http'
	nikto_ssl = ' -ssl' if 'https' in service or 'ssl' in service else '' 

	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(http* or ssl*) and not (broadcast or dos or external or http-slowloris* or fuzzer)" -oN "{basedir}/{port}_http_nmap.txt" -oX "{basedir}/{port}_http_nmap.xml" {address}'),
			e('nmap-{port}')
		),
		(
			e('curl -i {scheme}://{address}:{port}/ -m 10 -o "{basedir}/{port}_http_index.html"'),
			e('curl-1-{port}')
		),
		(
			e('curl -i {scheme}://{address}:{port}/robots.txt -m 10 -o "{basedir}/{port}_http_robots.txt"'),
			e('curl-2-{port}')
		)
	])

	# wait for previous scan to finish, then:

	run_cmds([
		(
			e('gobuster -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 10 -u {scheme}://{address}:{port} -e -s "200,204,301,302,307,403,500" | tee "{basedir}/{port}_http_dirb.txt"'),
			e('gobuster-{port}')
		),
		(
			# -C all potentially slowing it down?
			e('nikto -h {scheme}://{address}:{port}{nikto_ssl} -o "{basedir}/{port}_http_nikto.txt"'),
			e('nikto-{port}')
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

def enum_smtp(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(smtp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_smtp_nmap.txt" -oX "{basedir}/{port}_smtp_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  POP3
#  nmap
#

def enum_pop3(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(pop3*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_pop3_nmap.txt" -oX "{basedir}/{port}_pop3_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  IMAP
#  nmap
#

def enum_imap(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(imap*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_imap_nmap.txt" -oX "{basedir}/{port}_imap_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  FTP
#  nmap
#

def enum_ftp(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(ftp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_ftp_nmap.txt" -oX "{basedir}/{port}_ftp_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  SMB
#  nmap, enum4linux, samrdump
#

def enum_smb(address, port, service, basedir):
	global hadsmb
	
	if hadsmb:
		return

	nmap_port = port
	if port == 139 or port == 445:
		nmap_port = '139,445'

	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {nmap_port} --script="(nbstat or smb*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 -oN "{basedir}/{port}_smb_nmap.txt" -oX "{basedir}/{port}_smb_nmap.xml" {address}'),
			e('nmap-{port}')
		),
		(
			e('enum4linux -a -M -l -d {address} | tee "{basedir}/{port}_smb_enum4linux.txt"'),
			e('enum4linux-{port}')
		),
		(
			e('python2 /usr/share/doc/python-impacket/examples/samrdump.py {address} {port}/SMB | tee "{basedir}/{port}_smb_samrdump.txt"'),
			e('samrdump-{port}')
		),
		(
			e('nbtscan -rvh {address} | tee "{basedir}/{port}_smb_nbtscan.txt"'),
			e('nbtscan-{port}')
		)
	])

	hadsmb = True


#
#  MSSQL
#  nmap
#

def enum_mssql(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(ms-sql*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=mssql.instance-port={port},smsql.username-sa,mssql.password-sa -oN "{basedir}/{port}_mssql_nmap.txt" -oX "{basedir}/{port}_mssql_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  MySQL
#  nmap
#

def enum_mysql(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(mysql*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_mysql_nmap.txt" -oX "{basedir}/{port}_mysql_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  Oracle
#  nmap
#

def enum_oracle(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(oracle*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_oracle_nmap.txt" -oX "{basedir}/{port}_oracle_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  NFS
#  nmap
#

def enum_nfs(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(rpcinfo or nfs*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_nfs_nmap.txt" -oX "{basedir}/{port}_nfs_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  SNMP
#  nmap, onesixtyone, snmpwalk
#

def enum_snmp(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(snmp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_snmp_nmap.txt" -oX "{basedir}/{port}_snmp_nmap.xml" {address}'),
			e('nmap-{port}')
		),
		(
			e('onesixtyone -c data/community -dd -o "{basedir}/{port}_snmp_onesixtyone.txt" {address}'),
			e('onesixtyone-{port}')
		),
		(
			e('snmpwalk -c public -v 1 {address} | tee "{basedir}/{port}_snmp_snmpwalk.txt"'),
			e('snmpwalk-{port}')
		)
	])


#
#  DNS
#  axfr with dig
#

def enum_dns(address, port, service, basedir):
	nmblookup = e("nmblookup -A {address} | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1")

	info('Running task {bgreen}nmblookup-{port}{rst}' + (' with {bblue}' + nmblookup + '{rst}' if verbose >= 1 else '...'))

	try:
		host = subprocess.check_output(nmblookup, shell=True, stderr=subprocess.DEVNULL).decode().strip()
	except subprocess.CalledProcessError:
		return

	run_cmds([
		(
			e('dig -p{port} @{host}.thinc.local thinc.local axfr > "{basedir}/{port}_dns_dig.txt"'),
			e('dig-{port}')
		)
	])


#
#  RDP
#  nmap
#

def enum_rdp(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(rdp*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{basedir}/{port}_rdp_nmap.txt" -oX "{basedir}/{port}_rdp_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  VNC
#  nmap
#

def enum_vnc(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV {nmapparams} -p {port} --script="(vnc* or realvnc*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 -oN "{basedir}/{port}_vnc_nmap.txt" -oX "{basedir}/{port}_vnc_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


#
#  Unidentified service
#  nmap
#

def enum_generic_tcp(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV -sC {nmapparams} -p {port} --script-args=unsafe=1 -oN "{basedir}/{port}_generic_tcp_nmap.txt" -oX "{basedir}/{port}_generic_tcp_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])

def enum_generic_udp(address, port, service, basedir):
	run_cmds([
		(
			e('nmap -vv --reason -sV -sC {nmapparams} -sU -p {port} --script-args=unsafe=1 -oN "{basedir}/{port}_generic_udp_nmap.txt" -oX "{basedir}/{port}_generic_udp_nmap.xml" {address}'),
			e('nmap-{port}')
		)
	])


# endregion

def scan_service(address, port, service):
	if port < 0:
		is_udp = True
		port *= -1
	else:
		is_udp = False

	info('Scanning service {bgreen}{service}{rst} on port {bgreen}{port}{rst}/{bgreen}{proto}{rst}...', proto='udp' if is_udp else 'tcp')
	basedir = os.path.join(outdir, address + srvname)
	os.makedirs(basedir, exist_ok=True)

	if bruteforce:
		error('Bruteforce-only mode is currently not available.')
		return

	if 'http' in service:
		enum_http(address, port, service, basedir)

	elif 'smtp' in service:
		enum_smtp(address, port, service, basedir)

	elif 'pop3' in service:
		enum_pop3(address, port, service, basedir)

	elif 'imap' in service:
		enum_imap(address, port, service, basedir)

	elif 'ftp' in service:
		enum_ftp(address, port, service, basedir)

	elif 'microsoft-ds' in service or 'netbios' in service:
		enum_smb(address, port, service, basedir)

	elif 'ms-sql' in service or 'msSql' in service:
		enum_mssql(address, port, service, basedir)

	elif 'mysql' in service:
		enum_mysql(address, port, service, basedir)

	elif 'oracle' in service:
		enum_oracle(address, port, service, basedir)

	elif 'nfs' in service or 'rpcbind' in service:
		enum_nfs(address, port, service, basedir)

	elif 'snmp' in service:
		enum_snmp(address, port, service, basedir)

	elif 'domain' in service or 'dns' in service:
		enum_dns(address, port, service, basedir)

	elif 'rdp' in service or 'ms-wbt-server' in service or 'ms-term-serv' in service:
		enum_rdp(address, port, service, basedir)

	elif 'vnc' in service:
		enum_vnc(address, port, service, basedir)

	elif not is_udp:
		warn('Service {byellow}{service}{rst} will be scanned generically.')

		enum_generic_tcp(address, port, service, basedir)

	else:
		if port <= 1024:
			warn('Service {byellow}{service}{rst} will be scanned generically.')
			
			enum_generic_udp(address, port, service, basedir)

		else:
			warn('Service {byellow}{service}{rst} will not be scanned generically.')

			with open(os.path.join(basedir, '0_untouched.txt'), 'a') as file:
				file.writelines(str(port) + '\t' + ('udp' if is_udp else 'tcp') + '\t' + service + '\n')


def scan_host(address):
	info('Scanning host {byellow}{address}{rst}...')
	basedir = os.path.join(outdir, address + srvname)
	os.makedirs(basedir, exist_ok=True)

	services = run_nmap(address)

	if any('unknown' in s for s in services):
		services = run_amap(services)

	if len(services) != 0:
		info('Starting scan of services...')

	if os.path.exists(os.path.join(basedir, '0_untouched.txt')):
		os.unlink(os.path.join(basedir, '0_untouched.txt'))

	for service in services:
		scan_service(*service)


if __name__ == '__main__':
	if 'COLUMNS' not in os.environ:
		os.environ['COLUMNS'] = str(shutil.get_terminal_size((80, 20)).columns)

	parser = argparse.ArgumentParser(description='Network reconnaissance tool for enumerating the everliving fuck out of a host.')
	parser.add_argument('address', action='store', help='address of the host.')
	parser.add_argument('port', action='store', type=int, help='port of the service, if scanning only one port', nargs='?')
	parser.add_argument('service', action='store', help='type of the service, when port is specified', nargs='?')
	parser.add_argument('-b', '--bruteforce', action='store_true', help='only bruteforce credentials with hydra')
	parser.add_argument('-d', '--dry-run', action='store_true', help='does not invoke commands')
	parser.add_argument('-p', '--parallel', action='store_true', help='runs multiple commands in parallel, if set')
	parser.add_argument('-v', '--verbose', action='count', help='enable verbose output, repeat for more verbosity')
	parser.add_argument('-n', '--name', action='store', help='name of the machine to append to the output name')
	parser.add_argument('-o', '--output', action='store', default='results', help='output directory for the results')
	parser.add_argument('--nmap', action='store', default='-Pn --min-rate=400 -T4 --script-timeout 10m', help='additional nmap arguments')
	parser.add_argument('--hydra', action='store', default='-L data/users -P data/passwords -t 16 -f', help='additional hydra arguments')
	parser.error = lambda s: fail(s[0].upper() + s[1:])
	args = parser.parse_args()

	outdir      = args.output
	verbose     = args.verbose if args.verbose is not None else 0
	dryrun      = args.dry_run
	bruteforce  = args.bruteforce
	nmapparams  = args.nmap
	hydraparams = args.hydra
	srvname     = '_' + args.name if args.name else ''

	atexit.register(lambda: os.system('stty sane'))

	if args.port is not None:
		if args.service is None:
			fail('Service type is required when scanning only one port.')

		scan_service(args.address, args.port, args.service)
	else:
		scan_host(args.address)

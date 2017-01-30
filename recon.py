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
import argparse
import threading
import subprocess
import multiprocessing
from libnmap.parser import NmapParser
from colorama import init, Fore, Back, Style

init()

verbose = 0
dryrun  = False
outdir  = ''

# region Colors


def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', file=sys.stdout):
	print(color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET, *args, sep=sep, end=end, file=file)


def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout):
	if verbose >= 1:
		cprint(*args, color=color, char='-', sep=sep, end=end, file=file)


def info(*args, sep=' ', end='\n', file=sys.stdout):
	cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file)


def warn(*args, sep=' ', end='\n', file=sys.stderr):
	cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file)


def error(*args, sep=' ', end='\n', file=sys.stderr):
	cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file)


def fail(*args, sep=' ', end='\n', file=sys.stderr):
	error(*args, sep=sep, end=end, file=file)
	exit(-1)


# endregion

# region Process Management


def dump_pipe(stream, stop_event=None, tag='?', color=Fore.BLUE):
	while stream.readable() and (stop_event is not None and not stop_event.is_set()):
		line = stream.readline().decode('utf-8').rstrip()

		if len(line) != 0:
			debug(color + '[' + Style.BRIGHT + tag + Style.NORMAL + '] ' + Fore.RESET + line, color=color)


def run_cmd(cmd, tag='?', redirect=None):
	if redirect is None:
		redirect = verbose >= 2

	info(('Skipping' if dryrun else 'Running') + ' task ' + Fore.GREEN + Style.BRIGHT + tag + Style.NORMAL + Fore.RESET + (' with ' + Fore.BLUE + Style.BRIGHT + cmd + Style.NORMAL + Fore.RESET if verbose >= 1 else '...'))

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
		error('Task ' + Fore.RED + Style.BRIGHT + tag + Style.NORMAL + Fore.RESET + ' returned non-zero exit code: ' + str(ret))
	else:
		info('Task ' + Fore.GREEN + Style.BRIGHT + tag + Style.NORMAL + Fore.RESET + ' finished successfully.')

	return ret == 0


def run_cmds(cmds):
	procs = []

	for cmd in cmds:
		proc = multiprocessing.Process(target=run_cmd, args=cmd)
		procs.append(proc)
		proc.start()

	for proc in procs:
		if proc.is_alive():
			proc.join()


# endregion

# region Host Discovery


def run_nmap(address):
	out = os.path.join(outdir, address)
	run_cmds([
		('nmap -v -sV -sC -T5 -p- -oN "' + out + '/0_tcp_nmap.txt" -oX "' + out + '/0_tcp_nmap.xml" ' + address, 'nmap-tcp'),
		('nmap -v -sV --version-intensity 0 -sC -sU -T5 -oN "' + out + '/0_udp_nmap.txt" -oX "' + out + '/0_udp_nmap.xml" ' + address, 'nmap-udp')
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

		info('Service ' + Fore.GREEN + Style.BRIGHT + str(service.port) + Style.NORMAL + Fore.RESET + '/' + Fore.GREEN + Style.BRIGHT + service.protocol + Style.NORMAL + Fore.RESET + ' is ' + Fore.GREEN + Style.BRIGHT + service.service + Style.NORMAL + Fore.RESET + (' running ' + Fore.GREEN + service.service_dict['product'] + Fore.RESET if 'product' in service.service_dict else '') + (' version ' + Fore.GREEN + service.service_dict['version'] + Fore.RESET if 'version' in service.service_dict else ''))
		services.append((address, service.port * -1 if service.protocol == 'udp' else service.port, service.service))

	return services


def run_amap(services, only_unidentified=True):
	out = os.path.join(outdir, services[0][0])

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
		cmds.append(('amap -A -bqv -m -o "' + out + '/0_tcp_amap.txt" ' + services[0][0] + ' ' + ports_tcp.rstrip(','), 'amap-tcp'))

	if len(ports_udp) != 0:
		cmds.append(('amap -A -bqvu -m -o "' + out + '/0_udp_amap.txt" ' + services[0][0] + ' ' + ports_udp.rstrip(','), 'amap-udp'))

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
#  nmap, nikto, dirb
#

def enum_http(address, port, service, basedir):
	scheme = 'https' if 'https' in service or 'ssl' in service else 'http'

	run_cmds([
		('nmap -vv -sV -T5 -Pn -p ' + str(port) + ' --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-* -oN "' + basedir + '/' + str(port) + '_http_nmap.txt" -oX "' + basedir + '/' + str(port) + '_http_nmap.xml" ' + address, 'nmap-' + str(port)),
		('curl -I ' + scheme + '://' + address + ':' + str(port) + '/ -o "' + basedir + '/' + str(port) + '_http_index.html"', 'curl-1-' + str(port)),
		('curl -I ' + scheme + '://' + address + ':' + str(port) + '/robots.txt -o "' + basedir + '/' + str(port) + '_http_robots.txt"', 'curl-2-' + str(port))
	])
	run_cmds([
		('dirb ' + scheme + '://' + address + ':' + str(port) + ' -o "' + basedir + '/' + str(port) + '_http_dirb.txt" -r', 'dirb-' + str(port)),
		('nikto -h ' + scheme + '://' + address + ' -p ' + str(port) + ' -o "' + basedir + '/' + str(port) + '_http_nikto.txt"', 'nikto-' + str(port))
	])


#
#  SMTP
#  nmap
#

def enum_smtp(address, port, service, basedir):
	run_cmds([
		('nmap -vv -sV -T5 -Pn -p ' + str(port) + ' --script=smtp-commands,smtp-enum-users,smtp-vuln-* -oN "' + basedir + '/' + str(port) + '_smtp_nmap.txt" -oX "' + basedir + '/' + str(port) + '_smtp_nmap.xml" ' + address, 'nmap-' + str(port))
	])


#
#  FTP
#  nmap, [hydra]
#

def enum_ftp(address, port, service, basedir):
	run_cmds([
		('nmap -vv -sV -T5 -Pn -p ' + str(port) + ' --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-* -oN "' + basedir + '/' + str(port) + '_ftp_nmap.txt" -oX "' + basedir + '/' + str(port) + '_ftp_nmap.xml" ' + address, 'nmap-' + str(port)),
		# ('hydra -v -L /usr/share/nmap/nselib/data/usernames.lst -P /usr/share/nmap/nselib/data/passwords.lst -t 8 -f -o "' + basedir + '/' + str(port) + '_ftp_hydra.txt" -u ' + address + ' -s ' + str(port) + ' ftp', 'hydra-' + str(port))
	])


#
#  SMB
#  nmap, enum4linux, samrdump
#

def enum_smb(address, port, service, basedir):
	run_cmds([
		('nmap -vv -sV -T5 -Pn -p ' + str(port) + ' --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-*,smbv2-enabled.nse -oN "' + basedir + '/' + str(port) + '_smb_nmap.txt" -oX "' + basedir + '/' + str(port) + '_smb_nmap.xml" ' + address, 'nmap-' + str(port)),
		('enum4linux -a ' + address + ' | tee "' + basedir + '/' + str(port) + '_smb_enum4linux.txt" ' + address, 'enum4linux-' + str(port)),
		('python2 /usr/share/doc/python-impacket/examples/samrdump.py ' + address + ' ' + str(port) + '/SMB | tee "' + basedir + '/' + str(port) + '_smb_samrdump.txt"', 'samrdump-' + str(port))
	])


#
#  MSSQL
#  nmap
#

def enum_mssql(address, port, service, basedir):
	run_cmds([
		('nmap -vv -sV -T5 -Pn -p ' + str(port) + ' --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN "' + basedir + '/' + str(port) + '_mssql_nmap.txt" -oX "' + basedir + '/' + str(port) + '_mssql_nmap.xml" ' + address, 'nmap-' + str(port))
	])


#
#  SSH
#  [hydra]
#

def enum_ssh(address, port, service, basedir):
	run_cmds([
		# ('hydra -v -L /usr/share/nmap/nselib/data/usernames.lst -P /usr/share/nmap/nselib/data/passwords.lst -t 8 -f -o "' + basedir + '/' + str(port) + '_ssh_hydra.txt" -u ' + address + ' -s ' + str(port) + ' ssh', 'hydra-' + str(port))
	])


#
#  SNMP
#  onesixtyone, snmpwalk
#

def enum_snmp(address, port, service, basedir):
	run_cmds([
		('onesixtyone -dd -o "' + basedir + '/' + str(port) + '_snmp_onesixtyone.txt" ' + address, 'onesixtyone-' + str(port)),
		('snmpwalk -c public -v 1 ' + address + ' | tee "' + basedir + '/' + str(port) + '_snmp_snmpwalk.txt"', 'snmpwalk-' + str(port))
	])


#
#  DNS
#  axfr with dig
#

def enum_dns(address, port, service, basedir):
	nmblookup = 'nmblookup -A ' + address + " | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1"

	info('Running task ' + Fore.GREEN + Style.BRIGHT + 'nmblookup-' + str(port) + Style.NORMAL + Fore.RESET + (' with ' + Fore.BLUE + Style.BRIGHT + nmblookup + Style.NORMAL + Fore.RESET if verbose >= 1 else '...'))

	try:
		host = subprocess.check_output(nmblookup, shell=True, stderr=subprocess.DEVNULL).strip()
	except subprocess.CalledProcessError:
		return

	run_cmds([
		('dig @' + host + '.thinc.local thinc.local axfr > "' + basedir + '/' + str(port) + '_dns_dig.txt"', 'dig-' + str(port)),
	])


# endregion

def scan_service(address, port, service):
	if port < 0:
		is_udp = True
		port *= -1
	else:
		is_udp = False

	info('Scanning service ' + Fore.GREEN + Style.BRIGHT + service + Style.NORMAL + Fore.RESET + ' on port ' + Fore.GREEN + Style.BRIGHT + str(port) + Style.NORMAL + Fore.RESET + '/' + Fore.GREEN + Style.BRIGHT + ('udp' if is_udp else 'tcp') + Style.NORMAL + Fore.RESET + '...')
	basedir = os.path.join(outdir, address)
	os.makedirs(basedir, exist_ok=True)

	if 'http' in service:
		enum_http(address, port, service, basedir)
	elif 'smtp' in service:
		enum_smtp(address, port, service, basedir)
	elif 'ftp' in service:
		enum_ftp(address, port, service, basedir)
	elif 'microsoft-ds' in service or 'netbios-ssn' in service:
		enum_smb(address, port, service, basedir)
	elif 'ms-sql' in service:
		enum_mssql(address, port, service, basedir)
	elif 'ssh' in service:
		enum_ssh(address, port, service, basedir)
	elif 'snmp' in service:
		enum_snmp(address, port, service, basedir)
	elif 'domain' in service or 'dns' in service:
		enum_dns(address, port, service, basedir)
	else:
		warn('Service ' + Fore.YELLOW + Style.BRIGHT + service + Style.NORMAL + Fore.RESET + ' has no scanner support.')

		with open(os.path.join(basedir, '0_untouched.txt'), 'a') as file:
			file.writelines(str(port) + '\t' + ('udp' if is_udp else 'tcp') + '\t' + service + '\n')


def scan_host(address):
	info('Scanning host ' + Fore.YELLOW + Style.BRIGHT + address + Style.NORMAL + Fore.RESET + '...')
	basedir = os.path.join(outdir, address)
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
	parser = argparse.ArgumentParser(description='Network reconnaissance tool for enumerating the everliving fuck out of a host.')
	parser.add_argument('address', action='store', help='address of the host.')
	parser.add_argument('port', action='store', type=int, help='port of the service, if scanning only one port', nargs='?')
	parser.add_argument('service', action='store', help='type of the service, when port is specified', nargs='?')
	parser.add_argument('-v', '--verbose', action='count', help='enable verbose output, repeat for more verbosity')
	parser.add_argument('-n', '--dry-run', action='store_true', help='does not invoke commands')
	parser.add_argument('-o', '--output', action='store', default='results', help='output directory for the results')
	parser.error = lambda s: fail(s[0].upper() + s[1:])
	args = parser.parse_args()

	outdir  = args.output
	verbose = args.verbose if args.verbose is not None else 0
	dryrun  = args.dry_run

	if args.port is not None:
		if args.service is None:
			fail('Service type is required when scanning only one port.')

		scan_service(args.address, args.port, args.service)
	else:
		scan_host(args.address)

	os.system('stty sane')

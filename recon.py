#!/usr/bin/env python3
import sys
import os
import csv
import threading
import multiprocessing
import subprocess
import argparse
from libnmap.parser import NmapParser
from colorama import init, Fore, Back, Style

init()

verbose = False
dryrun  = False
outdir  = ''

# region Colors


def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', file=sys.stdout):
	print(color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET, *args, sep=sep, end=end, file=file)


def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout):
	if verbose:
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


def run_cmd(cmd, tag='?', redirect=True):
	if dryrun:
		return True

	proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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
		error(Fore.RED + Style.BRIGHT + tag + Style.NORMAL + Fore.RESET + ' returned non-zero exit code: ' + str(ret))
	else:
		info(Fore.GREEN + Style.BRIGHT + tag + Style.NORMAL + Fore.RESET + ' finished successfully.')

	return ret == 0


# endregion

def run_nmap(addr):
	out = os.path.join(outdir, addr, 'nmap')
	cmd_tcp = 'nmap -v -sV -sC -T5 -p- -oN "' + out + '_tcp.txt" -oX "' + out + '_tcp.xml" ' + addr
	cmd_udp = 'nmap -v -sV --version-intensity 0 -sC -sU -T5 -oN "' + out + '_udp.txt" -oX "' + out + '_udp.xml" ' + addr

	debug('Running ' + Fore.BLUE + Style.BRIGHT + cmd_tcp + Style.NORMAL + Fore.RESET)
	proc_tcp = multiprocessing.Process(target=run_cmd, args=(cmd_tcp, 'nmap-tcp'))
	proc_tcp.start()

	debug('Running ' + Fore.BLUE + Style.BRIGHT + cmd_udp + Style.NORMAL + Fore.RESET)
	proc_udp = multiprocessing.Process(target=run_cmd, args=(cmd_udp, 'nmap-udp'))
	proc_udp.start()

	proc_tcp.join()
	proc_udp.join()

	nmap_svcs = []

	if os.path.exists(out + '_tcp.xml'):
		report = NmapParser.parse_fromfile(out + '_tcp.xml')
		nmap_svcs += report.hosts[0].services

	if os.path.exists(out + '_udp.xml'):
		report = NmapParser.parse_fromfile(out + '_udp.xml')
		nmap_svcs += report.hosts[0].services

	services  = []
	nmap_svcs = sorted(nmap_svcs, key=lambda s: s.port)

	for service in nmap_svcs:
		if 'open' not in service.state:
			continue

		info('Service ' + Fore.GREEN + Style.BRIGHT + str(service.port) + Style.NORMAL + Fore.RESET + '/' + Fore.GREEN + Style.BRIGHT + service.protocol + Style.NORMAL + Fore.RESET + ' is ' + Fore.GREEN + Style.BRIGHT + service.service + Style.NORMAL + Fore.RESET + (' running ' + Fore.GREEN + service.service_dict['product'] + Fore.RESET if 'product' in service.service_dict else '') + (' version ' + Fore.GREEN + service.service_dict['version'] + Fore.RESET if 'version' in service.service_dict else ''))
		services.append((addr, service.port * -1 if service.protocol == 'udp' else service.port, service.service))

	return services


def run_amap(services, only_unidentified=True):
	out = os.path.join(outdir, services[0][0], 'amap')

	ports_tcp = ''
	ports_udp = ''

	for service in services:
		if only_unidentified and 'unknown' not in service[2]:
			continue

		if service[1] < 0:
			ports_udp += str(service[1] * -1) + ','
		else:
			ports_tcp += str(service[1]) + ','

	if len(ports_tcp) != 0:
		cmd_tcp = 'amap -A -bqv -m -o "' + out + '_tcp.txt" ' + services[0][0] + ' ' + ports_tcp.rstrip(',')

		debug('Running ' + Fore.BLUE + Style.BRIGHT + cmd_tcp + Style.NORMAL + Fore.RESET)
		proc_tcp = multiprocessing.Process(target=run_cmd, args=(cmd_tcp, 'amap-tcp'))
		proc_tcp.start()

	if len(ports_udp) != 0:
		cmd_udp = 'amap -A -bqvu -m -o "' + out + '_udp.txt" ' + services[0][0] + ' ' + ports_udp.rstrip(',')

		debug('Running ' + Fore.BLUE + Style.BRIGHT + cmd_udp + Style.NORMAL + Fore.RESET)
		proc_udp = multiprocessing.Process(target=run_cmd, args=(cmd_udp, 'amap-udp'))
		proc_udp.start()

	if len(ports_tcp) != 0:
		proc_tcp.join()

	if len(ports_udp) != 0:
		proc_udp.join()

	amap_svcs = []

	if os.path.exists(out + '_tcp.txt'):
		with open(out + '_tcp.txt') as file:
			reader = csv.reader(file, delimiter=':', quotechar='"', dialect=csv.unix_dialect)
			for row in reader:
				if len(row) > 5 and not row[0].startswith('#'):
					amap_svcs.append((row[0], int(row[1]) * -1 if row[2] == 'udp' else int(row[1]), row[5]))

	if os.path.exists(out + '_udp.txt'):
		with open(out + '_udp.txt') as file:
			reader = csv.reader(file, delimiter=':', quotechar='"', dialect=csv.unix_dialect)
			for row in reader:
				if len(row) > 5 and not row[0].startswith('#'):
					amap_svcs.append((row[0], int(row[1]) * -1 if row[2] == 'udp' else int(row[1]), row[5]))

	for i, val in enumerate(services):
		for amap_svc in amap_svcs:
			if services[i][0] == amap_svc[0] and services[i][1] == amap_svc[1] and ('unknown' in services[i][2] or not only_unidentified):
				services[i] = amap_svc

	return services


def scan_service(addr, port, service):
	info('Scanning service ' + Fore.YELLOW + Style.BRIGHT + addr + Style.NORMAL + Fore.RESET + ':' + Fore.GREEN + Style.BRIGHT + str(port) + Style.NORMAL + Fore.RESET + '/' + Fore.GREEN + Style.BRIGHT + service + Style.NORMAL + Fore.RESET + '...')
	basedir = os.path.join(outdir, addr)
	os.makedirs(basedir, exist_ok=True)


def scan_host(addr):
	info('Scanning host ' + Fore.YELLOW + Style.BRIGHT + addr + Style.NORMAL + Fore.RESET + '...')
	basedir = os.path.join(outdir, addr)
	os.makedirs(basedir, exist_ok=True)

	services = run_nmap(addr)

	if any('unknown' in s for s in services):
		services = run_amap(services)

	for service in services:
		scan_service(*service)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Network reconnaissance tool for enumerating the everliving fuck out of a host.')
	parser.add_argument('address', action='store', help='address of the host.')
	parser.add_argument('port', action='store', type=int, help='port of the service, if scanning only one port', nargs='?')
	parser.add_argument('service', action='store', help='type of the service, when port is specified', nargs='?')
	parser.add_argument('-v', '--verbose', action='store_true', help='enable verbose output')
	parser.add_argument('-n', '--dry-run', action='store_true', help='does not invoke commands')
	parser.add_argument('-o', '--output', action='store', default='results', help='output directory for the results')
	parser.error = lambda s: fail(s[0].upper() + s[1:])
	args = parser.parse_args()

	outdir  = args.output
	verbose = args.verbose
	dryrun  = args.dry_run

	if args.port is not None:
		if args.service is None:
			fail('Service type is required when scanning only one port.')

		scan_service(args.address, args.port, args.service)
	else:
		scan_host(args.address)

#!/usr/bin/env python3
#
#    Vulnerability database query tool for exploitation assistance.
#    Copyright (C) 2017 RoliSoft <root@rolisoft.net>
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import argparse
import os
import re
import shutil
import sys
import math
import struct
import sqlite3
from colorama import init, Fore, Back, Style
from libnmap.parser import NmapParser

init()

dumpall = False
conn = None
c = None

# region Colors


def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', file=sys.stdout):
	print(color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET, *args, sep=sep, end=end, file=file)


def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout):
	#if verbose >= 1:
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


def liprint(*args, color=Fore.BLUE, char='>>>', sep=' ', end='\n', file=sys.stdout):
	print(color + Style.BRIGHT + char + Style.NORMAL + Fore.RESET, *args, sep=sep, end=end, file=file)


# endregion

# region SQLite3 extensions


# https://en.wikipedia.org/wiki/Okapi_BM25
# borrowed from https://gist.github.com/saaj/fdc8e6351d07fbb1a511
def bm25(raw_match_info, column_index, k1 = 1.2, b = 0.75):
	match_info = [struct.unpack('@I', raw_match_info[i:i+4])[0] for i in range(0, len(raw_match_info), 4)]
	score = 0.0
	p, c = match_info[:2]
	n_idx = 2 + (3 * p * c)
	a_idx = n_idx + 1
	l_idx = a_idx + c
	n = match_info[n_idx]
	a = match_info[a_idx: a_idx + c]
	l = match_info[l_idx: l_idx + c]

	total_docs = n
	avg_length = float(a[column_index])
	doc_length = float(l[column_index])
	D = 0 if avg_length == 0 else 1 - b + (b * (doc_length / avg_length))

	for phrase in range(p):
		x_idx = 2 + (3 * column_index * (phrase + 1))
		term_freq = float(match_info[x_idx])
		term_matches = float(match_info[x_idx + 2])
		idf = max(math.log((total_docs - term_matches + 0.5) / (term_matches + 0.5)), 0)
		denom = term_freq + (k1 * D)
		rhs = 0 if denom == 0 else (term_freq * (k1 + 1)) / denom
		score += (idf * rhs)

	return score


# endregion

# region Man functions


def fuzzy_find_cpe(name, version=None):
	conn.create_function('bm25', 2, bm25)

	name = re.sub('\s\s*', ' ', name.lower()).strip().replace(' ', ' OR ')

	if not version:
		query  = 'select cpe, bm25(matchinfo(names, \'pcxnal\'), 1) as rank from names where name match ? and rank > 0 order by rank desc limit 1'
		params = [name]
	else:
		query  = 'select cpe, bm25(matchinfo(names, \'pcxnal\'), 1) as rank from names where name match ? and name like ? and rank > 0 order by rank desc limit 1'
		params = [name, '%' + version + '%']

	for row in c.execute(query, params):
		return row[0]

	return None


def get_vulns(cpe):
	vulns = []

	if cpe.startswith('cpe:/'):
		cpe = cpe[5:]

	cparts = cpe.split(':')
	if len(cparts) < 4 and not dumpall:
		warn('Name ' + Fore.YELLOW + Style.BRIGHT + 'cpe:/' + cpe + Style.NORMAL + Fore.RESET + ' has no version. Use ' + Fore.BLUE + Style.BRIGHT + '-a' + Style.NORMAL + Fore.RESET + ' to dump all vulnerabilities.')
		return vulns

	for row in c.execute('select cve, cpe, date, description, availability from affected join vulns on vulns.id = affected.vuln_id where cpe like ? or cpe like ? order by id desc', (cpe, cpe + ':%')):
		vulns.append(row)

	return vulns


def get_vulns_cli(cpe):
	vulns = get_vulns(cpe)

	if not cpe.startswith('cpe:/'):
		cpe = 'cpe:/' + cpe

	if not vulns:
		info('Entry ' + Fore.YELLOW + Style.BRIGHT + cpe + Style.NORMAL + Fore.RESET + ' has no vulnerabilities.')
		return

	info('Entry ' + Fore.YELLOW + Style.BRIGHT + cpe + Style.NORMAL + Fore.RESET + ' has the following vulnerabilities:')

	cols = int(os.environ['COLUMNS'])

	for vuln in vulns:
		color = Fore.RED if vuln[4] == 'C' else Fore.YELLOW if vuln[4] == 'P' else Fore.RESET

		descr = vuln[3]
		if len(descr) > cols - 18:
			descr = descr[:cols - 20] + ' >'

		descr = re.sub(r'\b(denial.of.service|execute|arbitrary|code|overflow|gain|escalate|privileges?)\b', Fore.GREEN + Style.BRIGHT + r'\1' + Style.NORMAL + Fore.RESET, descr)

		liprint(color + Style.BRIGHT + 'CVE-' + vuln[0] + Style.NORMAL + Fore.RESET + ' ' + descr)


def process_nmap(file):
	report = NmapParser.parse_fromfile(file)

	for host in report.hosts:
		for service in host.services:
			msg  = 'Service ' + Fore.GREEN + Style.BRIGHT + host.address + Style.NORMAL + Fore.RESET + ':' + Fore.GREEN + Style.BRIGHT + str(service.port) + Style.NORMAL + Fore.RESET + '/' + Fore.GREEN + Style.BRIGHT + service.protocol + Style.NORMAL + Fore.RESET

			if 'cpelist' in service.service_dict and len(service.service_dict['cpelist']) > 0:
				info(msg + ' is ' + Fore.YELLOW + Style.BRIGHT + (Style.NORMAL + Fore.RESET + ', ' + Fore.YELLOW + Style.BRIGHT).join(service.service_dict['cpelist']) + Style.NORMAL + Fore.RESET)

				for cpe in service.service_dict['cpelist']:
					get_vulns_cli(cpe)

			elif 'product' in service.service_dict and len(service.service_dict['product']) > 0:
				product = service.service_dict['product'] if 'product' in service.service_dict else ''
				version = service.service_dict['version'] if 'version' in service.service_dict else ''
				extrainfo = service.service_dict['extrainfo'] if 'extrainfo' in service.service_dict else ''
				full = (product + ' ' + version + ' ' + extrainfo).strip()

				cpe = fuzzy_find_cpe(product + ' ' + extrainfo, version)
				if cpe is None:
					warn(msg + ' was identified as ' + Fore.BLUE + Style.BRIGHT + full + Style.NORMAL + Fore.RESET + ' with no matching CPE name.')
				else:
					info(msg + ' was identified as ' + Fore.BLUE + Style.BRIGHT + full + Style.NORMAL + Fore.RESET + ' and fuzzy-matched to ' + Fore.YELLOW + Style.BRIGHT + 'cpe:/' + cpe + Style.NORMAL + Fore.RESET + '.')
					get_vulns_cli(cpe)
			else:
				warn(msg + ' was not identified.')


# endregion


if __name__ == '__main__':
	if 'COLUMNS' not in os.environ:
		os.environ['COLUMNS'] = str(shutil.get_terminal_size((80, 20)).columns)

	parser = argparse.ArgumentParser(description='Vulnerability database query tool for exploitation assistance.')
	parser.add_argument('query', action='store', help='CPE name, full name and version to fuzzy match, or path to nmap report (generated with -sV)')
	parser.add_argument('-a', '--all', action='store_true', help='dump all vulnerabilities for a CPE when no version is included (off by default)')
	parser.error = lambda s: fail(s[0].upper() + s[1:])
	args = parser.parse_args()

	dumpall = args.all

	conn = sqlite3.connect('vulns.db')
	c = conn.cursor()

	if args.query.lower().startswith('cpe:/'):
		info('Finding vulnerabilities for ' + Fore.GREEN + Style.BRIGHT + args.query.lower() + Style.NORMAL + Fore.RESET + '...')
		get_vulns_cli(args.query.lower())

	elif os.path.isfile(args.query):
		info('Processing nmap report ' + Fore.GREEN + Style.BRIGHT + args.query + Style.NORMAL + Fore.RESET + '...')
		process_nmap(args.query)

	else:
		info('Performing fuzzy matching for ' + Fore.GREEN + Style.BRIGHT + args.query + Style.NORMAL + Fore.RESET + '...')

		cpe = fuzzy_find_cpe(args.query)
		if cpe is None:
			error('Failed to resolve query to a CPE name.')
		else:
			info('Fuzzy-matched query to name ' + Fore.YELLOW + Style.BRIGHT + 'cpe:/' + cpe + Style.NORMAL + Fore.RESET)
			get_vulns_cli(cpe)

	conn.close()

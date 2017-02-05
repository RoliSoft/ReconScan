#!/usr/bin/env python3
#
#    Vulnerability database query tool for exploitation assistance.
#    Copyright (C) 2017 RoliSoft <root@rolisoft.net>
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#
import os
import re
import sys
import math
import glob
import struct
import shutil
import sqlite3
import argparse
import datetime
from lxml import etree
from urllib import parse
from libnmap.parser import NmapParser
from colorama import init, Fore, Back, Style

init()

dumpall = False
conn = None
c = None

# region Colors


def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', file=sys.stdout):
	print(color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET, *args, sep=sep, end=end, file=file)


def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout):
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

# region Database update


def download_archives(url, out, uncompress=True):
	os.system('wget "' + url + '" -O "' + out + '"')

	if uncompress:
		os.system('gzip -v -d "' + out + '"')


def download_nvd_dbs():
	os.makedirs('nvd', exist_ok=True)

	if os.path.exists('nvd/cpe-dict.xml'):
		os.unlink('nvd/cpe-dict.xml')

	info('Downloading CPE dictionary...')
	download_archives('https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz', 'nvd/cpe-dict.xml.gz')

	if os.path.exists('nvd/cpe-aliases.lst'):
		os.unlink('nvd/cpe-aliases.lst')

	info('Downloading CPE aliases...')
	download_archives('https://anonscm.debian.org/viewvc/secure-testing/data/CPE/aliases?view=co', 'nvd/cpe-aliases.lst', False)

	currentyear = datetime.datetime.now().year

	for year in range(2002, currentyear):
		if os.path.exists('nvd/cve-items-' + str(year) + '.xml'):
			debug('Not downloading CVE entries for year ' + str(year) + ': file already exists.')
			continue

		info('Downloading CVE entries for year ' + str(year) + '...')
		download_archives('https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-' + str(year) + '.xml.gz', 'nvd/cve-items-' + str(year) + '.xml.gz')

	if os.path.exists('nvd/cve-items-' + str(currentyear) + '.xml'):
		os.unlink('nvd/cve-items-' + str(currentyear) + '.xml')

	info('Downloading CVE entries for year ' + str(currentyear) + '...')
	download_archives('https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-' + str(currentyear) + '.xml.gz', 'nvd/cve-items-' + str(currentyear) + '.xml.gz')


def parse_nvd_dbs():
	info('Initiating XML parsing...')

	names = []

	info('Parsing file ' + Fore.GREEN + Style.BRIGHT + 'nvd/cpe-dict.xml' + Style.NORMAL + Fore.RESET + '...')

	tree = etree.parse('nvd/cpe-dict.xml')
	root = tree.getroot()

	for entry in root.findall('{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
		name = parse.unquote(entry.attrib['name'][5:])
		titles = entry.findall('{http://cpe.mitre.org/dictionary/2.0}title')
		if titles is not None:
			if len(titles) > 1:
				for localtitle in titles:
					if localtitle.attrib['{http://www.w3.org/XML/1998/namespace}lang'] == 'en-US':
						title = localtitle
			else:
				title = titles[0]

			names.append([name, title.text])

	aliases = []

	info('Parsing file ' + Fore.GREEN + Style.BRIGHT + 'nvd/cpe-aliases.lst' + Style.NORMAL + Fore.RESET + '...')

	with open('nvd/cpe-aliases.lst') as file:
		alias_group = []

		for line in file:
			if line.startswith('#'):
				continue

			if len(line.strip()) == 0:
				if len(alias_group) != 0:
					aliases.append(alias_group)
					alias_group = []
				continue

			alias_group.append(parse.unquote(line.strip()[5:]))

	vulns = []

	for file in glob.glob('nvd/cve-items-*.xml'):
		info('Parsing file ' + Fore.GREEN + Style.BRIGHT + file + Style.NORMAL + Fore.RESET + '...')

		tree = etree.parse(file)
		root = tree.getroot()

		for entry in root.findall('{http://scap.nist.gov/schema/feed/vulnerability/2.0}entry'):
			vuln = {'id': None, 'date': None, 'description': None, 'availability': None, 'affected': []}

			id = entry.find('{http://scap.nist.gov/schema/vulnerability/0.4}cve-id')
			if id is not None:
				vuln['id'] = id.text[4:]

			date = entry.find('{http://scap.nist.gov/schema/vulnerability/0.4}published-datetime')
			if date is not None:
				vuln['date'] = date.text

			description = entry.find('{http://scap.nist.gov/schema/vulnerability/0.4}summary')
			if description is not None:
				vuln['description'] = description.text

			cvss = entry.find('{http://scap.nist.gov/schema/vulnerability/0.4}cvss')
			if cvss is not None:
				metrics = cvss.find('{http://scap.nist.gov/schema/cvss-v2/0.2}base_metrics')
				if metrics is not None:
					availability = metrics.find('{http://scap.nist.gov/schema/cvss-v2/0.2}availability-impact')
					if availability is not None:
						vuln['availability'] = availability.text[0]

			affected = entry.find('{http://scap.nist.gov/schema/vulnerability/0.4}vulnerable-software-list')
			if affected is not None:
				for item in affected:
					vuln['affected'].append(parse.unquote(item.text[5:]))

				vulns.append(vuln)

	info('Extracted ' + Fore.YELLOW + Style.BRIGHT + '{:,}'.format(len(vulns)) + Style.NORMAL + Fore.RESET + ' vulnerabilites.')

	return (names, aliases, vulns)


def create_vulndb(names, aliases, vulns):
	info('Initiating SQLite creation...')

	if os.path.isfile('vulns.db'):
		os.unlink('vulns.db')

	conn = sqlite3.connect('vulns.db')
	c = conn.cursor()

	c.execute('create table vulns (id integer primary key autoincrement, cve text, date datetime, description text, availability char(1))')
	c.execute('create table affected (vuln_id integer not null, cpe text, foreign key(vuln_id) references vulns(id))')
	c.execute('create table aliases (class int, cpe text)')
	# c.execute('create table names (cpe text, name text, foreign key(cpe) references affected(cpe))')
	c.execute('create virtual table names using fts4(cpe, name)')

	for vuln in vulns:
		c.execute('insert into vulns (cve, date, description, availability) values (?, ?, ?, ?)', [vuln['id'], vuln['date'], vuln['description'], vuln['availability']])

		id = c.lastrowid

		for affected in vuln['affected']:
			c.execute('insert into affected (vuln_id, cpe) values (?, ?)', [id, affected])

	for name in names:
		c.execute('insert into names (cpe, name) values (?, ?)', name)

	group_counter = 0
	for alias_group in aliases:
		for alias in alias_group:
			c.execute('insert into aliases (class, cpe) values (?, ?)', [group_counter, alias])

		group_counter += 1

	c.execute('create index cpe_vuln_idx on affected (cpe collate nocase)')
	c.execute('create index cpe_alias_cpe_idx on aliases (cpe collate nocase)')
	c.execute('create index cpe_alias_class_idx on aliases (class)')

	conn.commit()
	conn.close()

	info('Finished database creation.')


def update_database():
	download_nvd_dbs()
	(names, aliases, vulns) = parse_nvd_dbs()
	create_vulndb(names, aliases, vulns)


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


def get_cpe_aliases(cpe):
	cparts = cpe.split(':')

	cpebase = ':'.join(cparts[:3])
	version = ':'.join(cparts[3:])

	aliases = []

	for row in c.execute('select cpe from aliases where class = (select class from aliases where cpe like ?)', [cpebase]):
		alias = row[0]

		if version:
			alias += ':' + version

		aliases.append(alias)

	return aliases


def get_vulns(cpe):
	vulns = []

	if cpe.startswith('cpe:/'):
		cpe = cpe[5:]

	cparts = cpe.split(':')
	if len(cparts) < 4 and not dumpall:
		warn('Name ' + Fore.YELLOW + Style.BRIGHT + 'cpe:/' + cpe + Style.NORMAL + Fore.RESET + ' has no version. Use ' + Fore.BLUE + Style.BRIGHT + '-a' + Style.NORMAL + Fore.RESET + ' to dump all vulnerabilities.')
		return None

	aliases = get_cpe_aliases(cpe)

	if len(aliases) > 0:
		query  = ''
		params = []

		for alias in aliases:
			query += 'cpe like ? or cpe like ? or '
			params.append(alias)
			params.append(alias + ':%')

		query = query[:-4]

	else:
		query  = 'cpe like ? or cpe like ?'
		params = [cpe, cpe + ':%']

	for row in c.execute('select cve, cpe, date, description, availability from affected join vulns on vulns.id = affected.vuln_id where ' + query + ' order by id desc', params):
		vulns.append(row)

	return vulns


def get_vulns_cli(cpe):
	vulns = get_vulns(cpe)

	if not cpe.startswith('cpe:/'):
		cpe = 'cpe:/' + cpe

	if vulns is not None and len(vulns) == 0:
		info('Entry ' + Fore.YELLOW + Style.BRIGHT + cpe + Style.NORMAL + Fore.RESET + ' has no vulnerabilities.')
		return

	if vulns is None:
		# get_vulns() returns None on error, which is already printed to the user
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
	parser.add_argument('query', action='store', nargs='?', help='CPE name, full name and version to fuzzy match, or path to nmap report (generated with -sV)')
	parser.add_argument('-a', '--all', action='store_true', help='dump all vulnerabilities for a CPE when no version is included (off by default)')
	parser.add_argument('-u', '--update', action='store_true', help='download the CVE dumps and recreate the local database')
	parser.error = lambda s: fail(s[0].upper() + s[1:])
	args = parser.parse_args()

	if args.query is None:
		if args.update:
			update_database()
		else:
			parser.error('the following arguments are required: query')

		exit()

	dumpall = args.all

	if not os.path.isfile('vulns.db'):
		fail('Failed to find ' + Fore.GREEN + Style.BRIGHT + 'vulns.db' + Style.NORMAL + Fore.RESET + '. Use ' + Fore.BLUE + Style.BRIGHT + '-u' + Style.NORMAL + Fore.RESET + ' to download the dependencies and build the database.')

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

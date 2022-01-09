#!/usr/bin/env python3
#
#    Vulnerability database query tool for exploitation assistance.
#    Copyright (C) 2017 RoliSoft <root@rolisoft.net>
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU Affero General Public License, either version 3 of the License, or
#    (at your option) any later version.
#

import os
import re
import sys
import math
import glob
import gzip
import struct
import shutil
import sqlite3
import argparse
import datetime
import cysimdjson
from lxml import etree
from urllib import parse
from libnmap.parser import NmapParser
from lib.colors import debug, info, warn, error, fail, tally

dumpall = False
dumpexp = False
verbose = False
conn = None
c = None


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


def download_archives(url, out):
	os.system('wget "' + url + '" -O "' + out + '"')


def download_nvd_dbs():
	os.makedirs('nvd', exist_ok=True)

	if os.path.exists('nvd/cpe-dict.xml.gz') and (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime('nvd/cpe-dict.xml.gz'))).days > 1:
		os.unlink('nvd/cpe-dict.xml.gz')

	if not os.path.exists('nvd/cpe-dict.xml.gz'):
		info('Downloading CPE dictionary...')
		download_archives('https://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz', 'nvd/cpe-dict.xml.gz')
	else:
		debug('Not downloading CPE dictionary: file is less than 24 hours old.')

	if os.path.exists('nvd/cpe-aliases.lst') and (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime('nvd/cpe-aliases.lst'))).days > 1:
		os.unlink('nvd/cpe-aliases.lst')

	if not os.path.exists('nvd/cpe-aliases.lst'):
		info('Downloading CPE aliases...')
		download_archives('https://salsa.debian.org/dlange/debian_security_security-tracker_split_files_v2/-/raw/master/data/CPE/aliases', 'nvd/cpe-aliases.lst')
	else:
		debug('Not downloading CPE aliases: file is less than 24 hours old.')

	currentyear = datetime.datetime.now().year

	for year in range(2002, currentyear):
		if os.path.exists('nvd/cve-items-' + str(year) + '.json.gz'):
			debug('Not downloading CVE entries for year {year}: file already exists.')
			continue

		info('Downloading CVE entries for year {year}...')
		download_archives('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-' + str(year) + '.json.gz', 'nvd/cve-items-' + str(year) + '.json.gz')

	if os.path.exists('nvd/cve-items-' + str(currentyear) + '.json.gz') and (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime('nvd/cve-items-' + str(currentyear) + '.json.gz'))).days > 1:
		os.unlink('nvd/cve-items-' + str(currentyear) + '.json.gz')

	if not os.path.exists('nvd/cve-items-' + str(currentyear) + '.json.gz'):
		info('Downloading CVE entries for year {currentyear}...')
		download_archives('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-' + str(currentyear) + '.json.gz', 'nvd/cve-items-' + str(currentyear) + '.json.gz')
	else:
		debug('Not downloading CVE entries for year {currentyear}: file is less than 24 hours old.')


def parse_cpe_names():
	names = []

	info('Parsing file {bgreen}nvd/cpe-dict.xml.gz{rst}...')

	root = None
	with gzip.open('nvd/cpe-dict.xml.gz', 'r') as f:
		root = etree.fromstring(f.read())

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

	return names

def parse_cpe_aliases():
	aliases = []

	info('Parsing file {bgreen}nvd/cpe-aliases.lst{rst}...')

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

	return aliases

def parse_exploits():
	# TODO refactor this to use one code path for all lists

	exploitdb_names = None
	exploitdb_map = None

	if os.path.exists('nvd/exploitdb.lst'):
		info('Using curated {bblue}ExploitDB{rst} references.')

		exploitdb_names = {}
		exploitdb_map = {}

		with open('nvd/exploitdb.lst') as file:
			for line in file:
				if line.startswith('#'):
					continue

				fields = line.strip().split(';')
				cves = fields[1].split(',')

				exploitdb_names[fields[0]] = fields[2] if len(fields) > 2 else None

				for cve in cves:
					if cve not in exploitdb_map:
						exploitdb_map[cve] = []

					exploitdb_map[cve].append(fields[0])
	else:
		info('Using {bblue}ExploitDB{rst} links from CVE references.')

	secfocus_names = None
	secfocus_map = None

	if os.path.exists('nvd/securityfocus.lst'):
		info('Using curated {bblue}SecurityFocus{rst} references.')

		secfocus_names = {}
		secfocus_map = set()

		with open('nvd/securityfocus.lst') as file:
			for line in file:
				if line.startswith('#'):
					continue

				fields = line.strip().split(';')

				secfocus_names[fields[0]] = fields[1] if len(fields) > 1 else None
				secfocus_map.add(fields[0])
	else:
		info('Using {bblue}SecurityFocus{rst} links from CVE references.')

	metasploit_names = None
	metasploit_map = None

	if os.path.exists('nvd/metasploit.lst'):
		info('Using curated {bblue}Metasploit{rst} references.')

		metasploit_names = {}
		metasploit_map = {}

		with open('nvd/metasploit.lst') as file:
			for line in file:
				if line.startswith('#'):
					continue

				fields = line.strip().split(';')
				cves = fields[1].split(',')

				metasploit_names[fields[0]] = fields[2] if len(fields) > 2 else None

				for cve in cves:
					if cve not in metasploit_map:
						metasploit_map[cve] = []

					metasploit_map[cve].append(fields[0])

	l337day_names = None
	l337day_map = None

	if os.path.exists('nvd/1337day.lst'):
		info('Using curated {bblue}1337day{rst} references.')

		l337day_names = {}
		l337day_map = {}

		with open('nvd/1337day.lst') as file:
			for line in file:
				if line.startswith('#'):
					continue

				fields = line.strip().split(';')
				cves = fields[1].split(',')

				l337day_names[fields[0]] = fields[2] if len(fields) > 2 else None

				for cve in cves:
					if cve not in l337day_map:
						l337day_map[cve] = []

					l337day_map[cve].append(fields[0])

	return (exploitdb_names, exploitdb_map, secfocus_names, secfocus_map, metasploit_names, metasploit_map, l337day_names, l337day_map)

def parse_cve_items(exploits):
	(exploitdb_names, exploitdb_map, secfocus_names, secfocus_map, metasploit_names, metasploit_map, l337day_names, l337day_map) = exploits;

	vulns = []

	parser = cysimdjson.JSONParser()
	entries = None

	for file in sorted(glob.glob('nvd/cve-items-*.json.gz')):
		info('Parsing file {bgreen}{file}{rst}...')

		with gzip.open(file, 'rb') as f:
			entries = parser.parse_in_place(f.read()).at_pointer('/CVE_Items')

		for entry in entries:
			vuln = {'id': None, 'date': None, 'description': None, 'availability': None, 'affected': [], 'vendor': [], '_exploitdb': [], '_securityfocus': [], '_metasploit': [], '_l337day': []}

			vuln['id'] = entry['cve']['CVE_data_meta']['ID'][4:]
			vuln['date'] = entry['publishedDate']
			vuln['description'] = entry['cve']['description']['description_data'][0]['value']

			if 'baseMetricV2' in entry['impact']:
				vuln['availability'] = entry['impact']['baseMetricV2']['cvssV2']['accessComplexity']
			
			# TODO implement proper matching for CPEs with provided operators
			for node in entry['configurations']['nodes']:
				for child in node['children']:
					for cpe in child['cpe_match']:
						vuln['affected'].append(cpe['cpe23Uri'])

			for reference in entry['cve']['references']['reference_data']:
				url = reference['url']
				source = reference['refsource']
				tags = reference['tags']

				if 'Vendor Advisory' in tags:
					vuln['vendor'].append(url)

				elif source == 'EXPLOIT-DB':
					vuln['_exploitdb'].append(url)
				
				elif source == 'BID':
					vuln['_securityfocus'].append(url)

			# TODO refactor this to use one code path for all lists
			if exploitdb_map is not None and vuln['id'] in exploitdb_map:
				for expid in exploitdb_map[vuln['id']]:
					vuln['_exploitdb'].append(expid)

				vuln['_exploitdb'] = set(vuln['_exploitdb'])

				vuln['exploitdb'] = []
				for exploit in vuln['_exploitdb']:
					vuln['exploitdb'].append({'id': exploit, 'title': exploitdb_names[exploit] if exploit in exploitdb_names else None})

				vuln['_exploitdb'] = None
			else:
				vuln['exploitdb'] = []
				for exploit in vuln['_exploitdb']:
					vuln['exploitdb'].append({'id': exploit, 'title': None})
				vuln['_exploitdb'] = None

			if secfocus_map is not None and vuln['_securityfocus']:
				exploits = []

				for sfid in vuln['_securityfocus']:
					if sfid in secfocus_map:
						exploits.append(sfid)

				vuln['securityfocus'] = []
				for exploit in exploits:
					vuln['securityfocus'].append({'id': exploit, 'title': secfocus_names[exploit] if exploit in secfocus_names else None})

				vuln['_securityfocus'] = None
			else:
				vuln['securityfocus'] = []
				for exploit in vuln['_securityfocus']:
					vuln['securityfocus'].append({'id': exploit, 'title': None})
				vuln['_securityfocus'] = None

			if metasploit_map is not None and vuln['id'] in metasploit_map:
				for expid in metasploit_map[vuln['id']]:
					vuln['_metasploit'].append(expid)

				vuln['_metasploit'] = set(vuln['_metasploit'])

				vuln['metasploit'] = []
				for exploit in vuln['_metasploit']:
					vuln['metasploit'].append({'id': exploit, 'title': metasploit_names[exploit] if exploit in metasploit_names else None})

				vuln['_metasploit'] = None

			if l337day_map is not None and vuln['id'] in l337day_map:
				for expid in l337day_map[vuln['id']]:
					vuln['_l337day'].append(expid)

				vuln['_l337day'] = set(vuln['_l337day'])

				vuln['l337day'] = []
				for exploit in vuln['_l337day']:
					vuln['l337day'].append({'id': exploit, 'title': l337day_names[exploit] if exploit in l337day_names else None})

				vuln['_l337day'] = None

			vulns.append(vuln)

	info('Extracted {byellow}{vulncount:,}{rst} vulnerabilites.', vulncount=len(vulns))

	return vulns


def create_vulndb(names, aliases, vulns):
	info('Initiating SQLite creation...')

	if os.path.isfile('vulns.db'):
		os.unlink('vulns.db')

	conn = sqlite3.connect('vulns.db')
	c = conn.cursor()

	c.execute('create table vulns (id integer primary key autoincrement, cve text, date datetime, description text, availability char(1), vendor text)')
	c.execute('create table affected (vuln_id integer not null, cpe text, foreign key(vuln_id) references vulns(id))')
	c.execute('create table aliases (class int, cpe text)')
	c.execute('create table exploits (site int, sid text, cve text, title text)')
	# c.execute('create table names (cpe text, name text, foreign key(cpe) references affected(cpe))')
	c.execute('create virtual table names using fts4(cpe, name)')

	info('Creating tables {bgreen}vulns{rst}, {bgreen}affected{rst} and {bgreen}exploits{rst}...')

	for vuln in vulns:
		c.execute('insert into vulns (cve, date, description, availability, vendor) values (?, ?, ?, ?, ?)', [vuln['id'], vuln['date'], vuln['description'], vuln['availability'], '\x1e'.join(vuln['vendor']) if vuln['vendor'] else None])

		id = c.lastrowid

		for affected in vuln['affected']:
			c.execute('insert into affected (vuln_id, cpe) values (?, ?)', [id, affected[8:]])

		if 'exploitdb' in vuln:
			for exploit in vuln['exploitdb']:
				c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [1, exploit['id'], vuln['id'], exploit['title']])

		if 'securityfocus' in vuln:
			for exploit in vuln['securityfocus']:
				c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [2, exploit['id'], vuln['id'], exploit['title']])

		if 'metasploit' in vuln:
			for exploit in vuln['metasploit']:
				c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [5, exploit['id'], vuln['id'], exploit['title']])

		if 'l337day' in vuln:
			for exploit in vuln['l337day']:
				c.execute('insert into exploits (site, sid, cve, title) values (?, ?, ?, ?)', [10, exploit['id'], vuln['id'], exploit['title']])

	info('Creating table {bgreen}names{rst}...')

	for name in names:
		c.execute('insert into names (cpe, name) values (?, ?)', name)

	info('Creating table {bgreen}aliases{rst}...')

	group_counter = 0
	for alias_group in aliases:
		for alias in alias_group:
			c.execute('insert into aliases (class, cpe) values (?, ?)', [group_counter, alias])

		group_counter += 1

	info('Creating indices...')

	c.execute('create index cpe_vuln_idx on affected (cpe collate nocase)')
	c.execute('create index cpe_alias_cpe_idx on aliases (cpe collate nocase)')
	c.execute('create index cpe_alias_class_idx on aliases (class)')
	c.execute('create index cve_exploit_idx on exploits (cve, site)')

	conn.commit()
	conn.close()

	info('Finished database creation.')


def update_database():
	#download_nvd_dbs()

	#names    = parse_cpe_names()
	#aliases  = parse_cpe_aliases()
	exploits = parse_exploits()
	vulns    = parse_cve_items(exploits)

	#create_vulndb(names, aliases, vulns)


# endregion

# region Man functions


def fuzzy_find_cpe(name, version=None):
	conn.create_function('bm25', 2, bm25)

	if version is None:
		# try to figure out if version is supplied

		parts = re.split(r'\bv?(\d+(?:\.\d)?)', name, 1, re.I)

		if len(parts) > 1:
			name = parts[0]
			version = ''.join(parts[1:])

	name = re.sub('\s\s*', ' ', name.lower()).strip()#

	if not version:
		query  = 'select cpe, name, bm25(matchinfo(names, \'pcxnal\'), 1) as rank from names where name match ? and rank > 0 order by rank desc limit 10'
		params = [name]
	else:
		query  = 'select cpe, name, bm25(matchinfo(names, \'pcxnal\'), 1) as rank from names where name match ? and name like ? and rank > 0 order by rank desc limit 10'
		params = [name, '%' + version + '%']

	for row in c.execute(query, params):
		return row[0]

	# retry with laxer search

	name = name.replace(' ', ' OR ')

	if not version:
		params = [name]
	else:
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

	if verbose:
		if len(aliases) > 0:
			debug('Resolved aliases: {byellow}cpe:/' + ('{rst}, {byellow}cpe:/'.join(aliases)) + '{rst}.')
		else:
			debug('No known aliases.')

	return aliases


def get_vulns(cpe):
	vulns = []

	if cpe.startswith('cpe:/'):
		cpe = cpe[5:]

	cparts = cpe.split(':')
	if len(cparts) < 4 and not dumpall:
		warn('Name {byellow}cpe:/{cpe}{rst} has no version. Use {bblue}-a{rst} to dump all vulnerabilities.')
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


def get_exploits(cves):
	exploits = []

	params = ''
	for cve in cves:
		params += '?, '
	params = params.rstrip(', ')

	for row in c.execute('select site, sid, cve, title from exploits where cve in (' + params + ') order by cve desc, site asc', cves):
		exploits.append(row)

	return exploits


def get_vulns_cli(cpe):
	vulns = get_vulns(cpe)

	if not cpe.startswith('cpe:/'):
		cpe = 'cpe:/' + cpe

	if vulns is not None and len(vulns) == 0:
		info('Entry {byellow}{cpe}{rst} has no vulnerabilities.')
		return

	if vulns is None:
		# get_vulns() returns None on error, which is already printed to the user
		return

	if not dumpexp:
		info('Entry {byellow}{cpe}{rst} has the following vulnerabilities:')

	cols = int(os.environ['COLUMNS'])

	cves = []

	for vuln in vulns:
		cves.append(vuln[0])

		if dumpexp:
			continue

		color = '{red}' if vuln[4] == 'C' else '{yellow}' if vuln[4] == 'P' else '{crst}'

		descr = vuln[3]
		if len(descr) > cols - 18:
			descr = descr[:cols - 20] + ' >'

		descr = re.sub(r'\b(denial.of.service|execute|arbitrary|code|overflow|gain|escalate|privileges?)\b', r'{bgreen}\1{rst}', descr)

		tally(color + '{bright}CVE-{vuln[0]}{rst} ' + descr)

	exploits = get_exploits(cves)

	if exploits:
		info('Entry {byellow}{cpe}{rst} has the following public exploits:')

		last_cve = ''
		descr = ''

		for exploit in exploits:
			if last_cve != exploit[2]:
				if last_cve:
					tally('{bred}CVE-{last_cve}{rst} ' + descr)
					descr = ''

				last_cve = exploit[2]

			descr += '\n    - '
			if exploit[3] is not None:
				descr += '{bright}' + exploit[3] + '{srst}\n      '

			if exploit[0] == 1:
				descr += 'https://www.exploit-db.com/exploits/' + exploit[1]
			elif exploit[0] == 2:
				descr += 'http://www.securityfocus.com/bid/' + exploit[1] + '/exploit'
			elif exploit[0] == 5:
				descr += 'metasploit ' + exploit[1]
			elif exploit[0] == 10:
				descr += 'http://0day.today/exploit/' + exploit[1]
			else:
				descr += exploit[1]

		tally('{bred}CVE-{last_cve}{rst} ' + descr)
	else:
		info('Entry {byellow}{cpe}{rst} has no public exploits.')


def process_nmap(file):
	report = NmapParser.parse_fromfile(file)

	for host in report.hosts:
		for service in host.services:
			msg  = 'Service {bgreen}{host.address}{rst}:{bgreen}{service.port}{rst}/{bgreen}{service.protocol}{rst}'

			if 'cpelist' in service.service_dict and len(service.service_dict['cpelist']) > 0:
				info(msg + ' is {byellow}' + '{rst}, {byellow}'.join(service.service_dict['cpelist']) + '{rst}')

				for cpe in service.service_dict['cpelist']:
					get_vulns_cli(cpe)

			elif 'product' in service.service_dict and len(service.service_dict['product']) > 0:
				product = service.service_dict['product'] if 'product' in service.service_dict else ''
				version = service.service_dict['version'] if 'version' in service.service_dict else ''
				extrainfo = service.service_dict['extrainfo'] if 'extrainfo' in service.service_dict else ''
				full = (product + ' ' + version + ' ' + extrainfo).strip()

				cpe = fuzzy_find_cpe(product + ' ' + extrainfo, version)
				if cpe is None:
					warn(msg + ' was identified as {bblue}{full}{rst} with no matching CPE name.')
				else:
					info(msg + ' was identified as {bblue}{full}{rst} and fuzzy-matched to {byellow}cpe:/{cpe}{rst}.')
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
	parser.add_argument('-e', '--exploits', action='store_true', help='dump only vulnerabilities with public exploits available')
	parser.add_argument('-u', '--update', action='store_true', help='download the CVE dumps and recreate the local database')
	parser.add_argument('-v', '--verbose', action='store_true', help='increase verbosity')
	parser.error = lambda s: fail(s[0].upper() + s[1:])
	args = parser.parse_args()

	if args.query is None:
		if args.update:
			update_database()
		else:
			parser.error('the following arguments are required: query')

		exit()

	dumpall = args.all
	dumpexp = args.exploits
	verbose = args.verbose

	if not os.path.isfile('vulns.db'):
		fail('Failed to find {bgreen}vulns.db{rst}. Use {bblue}-u{rst} to download the dependencies and build the database.')

	conn = sqlite3.connect('vulns.db')
	c = conn.cursor()

	if args.query.lower().startswith('cpe:/'):
		info('Finding vulnerabilities for {bgreen}{query}{rst}...', query=args.query.lower())
		get_vulns_cli(args.query.lower())

	elif os.path.isfile(args.query):
		info('Processing nmap report {bgreen}{args.query}{rst}...')
		process_nmap(args.query)

	else:
		info('Performing fuzzy matching for {bgreen}{args.query}{rst}...')

		cpe = fuzzy_find_cpe(args.query)
		if cpe is None:
			error('Failed to resolve query to a CPE name.')
		else:
			info('Fuzzy-matched query to name {byellow}cpe:/{cpe}{rst}.')
			get_vulns_cli(cpe)

	conn.close()

#!/usr/bin/env python3
#
#    Passive network reconnaissance tool for service enumeration.
#    Copyright (C) 2021 RoliSoft <root@rolisoft.net>
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import os
import re
import yaml
import json
import html
import datetime
import requests
import argparse
import configparser
from lxml import etree
from lib.colors import debug, info, warn, error, fail


class WebBase:
	_config = None

	def __init__(self) -> None:
		if WebBase._config is None and os.path.isfile('precon.conf'):
			WebBase._config = configparser.RawConfigParser()
			WebBase._config.read('precon.conf')

	def config(self, key):
		if WebBase._config is not None and self.__class__.__name__ in WebBase._config and key in WebBase._config[self.__class__.__name__]:
			return WebBase._config[self.__class__.__name__][key]
		else:
			return None


class ShodanWeb(WebBase):
	def name(self):
		return "Shodan"

	def get(self, address):
		headers = {
			'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
			'cookie': self.config('cookies'),
			'referer': 'https://www.shodan.io/host/' + address,
			'authority': 'www.shodan.io',
			'pragma': 'no-cache',
			'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
			'accept-language': 'en-US,en;q=0.9',
			'cache-control': 'no-cache',
			'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'sec-fetch-site': 'same-origin',
			'sec-fetch-mode': 'navigate',
			'sec-fetch-user': '?1',
			'sec-fetch-dest': 'document',
			'upgrade-insecure-requests': '1'
		}

		req = requests.get('https://www.shodan.io/host/' + address + '/raw', headers=headers)
		if req.status_code != 200:
			error('Failed to get {bblue}Shodan{rst}/{byellow}{address}{rst}: status code is {bred}{req.status_code}{rst}.')
			return None

		match = re.search(r'let data = ({.+});', req.text)
		if not match or not match.group(1):
			error('Failed to get {bblue}Shodan{rst}/{byellow}{address}{rst}: could not extract data.')
			return None

		# use YAML to parse the JSON, as Shodan sometimes returns invalid escapes, which the YAML parser is more lax with
		data = None
		try:
			data = yaml.load(match.group(1), Loader=yaml.FullLoader)
		except:
			error('Failed to get {bblue}Shodan{rst}/{byellow}{address}{rst}: failed to parse data.')
			return None

		return data

	def enum(self, data):
		for svc in data['data']:
			info('Discovered service {bgreen}{svc[_shodan][module]}{rst} on port {bgreen}{svc[port]}{rst}/{bgreen}{svc[transport]}{rst}.')


class CensysWeb(WebBase):
	def name(self):
		return "Censys"

	def get(self, address):
		headers = {
			'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
			'cookie': self.config('cookies'),
			'referer': 'https://search.censys.io/hosts/' + address,
			'authority': 'search.censys.io',
			'pragma': 'no-cache',
			'cache-control': 'no-cache',
			'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
			'accept-language': 'en-US,en;q=0.9',
			'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'sec-fetch-site': 'same-origin',
			'sec-fetch-mode': 'navigate',
			'sec-fetch-user': '?1',
			'sec-fetch-dest': 'document',
			'upgrade-insecure-requests': '1'
		}

		req = requests.get('https://search.censys.io/hosts/' + address + '/data/json', headers=headers)
		if req.status_code != 200:
			error('Failed to get {bblue}Censys{rst}/{byellow}{address}{rst}: status code is {bred}{req.status_code}{rst}.')
			return None

		match = re.search(r'<pre><code class="language-json">({.+})</code></pre>', req.text, re.DOTALL)
		if not match or not match.group(1):
			error('Failed to get {bblue}Censys{rst}/{byellow}{address}{rst}: could not extract data.')
			return None

		json = match.group(1)
		json = re.sub(r'<a (?:href|class)=".*?</a>', '-', json)
		json = html.unescape(json)
		
		data = None
		try:
			data = yaml.load(json, Loader=yaml.FullLoader)
		except:
			error('Failed to get {bblue}Censys{rst}/{byellow}{address}{rst}: failed to parse data.')
			return None

		return data

	def enum(self, data):
		for svc in data['services']:
			info('Discovered service {bgreen}{service}{rst} on port {bgreen}{svc[port]}{rst}/{bgreen}{transport}{rst}.',
				service=svc['service_name'].lower(), transport=svc['transport_protocol'].lower())


class ZoomEyeWeb(WebBase):
	def name(self):
		return "ZoomEye"

	def get(self, address):
		headers = {
			'Connection': 'keep-alive',
			'Pragma': 'no-cache',
			'Cache-Control': 'no-cache',
			'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
			'Accept': 'application/json, text/plain, */*',
			'Cube-Authorization': 'undefined',
			'sec-ch-ua-mobile': '?0',
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
			'Cookie': self.config('cookies'),
			'sec-ch-ua-platform': '"macOS"',
			'Sec-Fetch-Site': 'same-origin',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Dest': 'empty',
			'Referer': 'https://www.zoomeye.org/searchResult?q=ip%3A%22' + address + '%22',
			'Accept-Language': 'en-US,en;q=0.9',
		}

		params = (
			('q', 'ip%3A%22' + address + '%22'),
			('page', '1'),
			('pageSize', '20'),
			('t', 'v4+v6+web'),
		)

		req = requests.get('https://www.zoomeye.org/search', headers=headers, params=params)
		if req.status_code != 200:
			error('Failed to get {bblue}ZoomEye{rst}/{byellow}{address}{rst}: status code is {bred}{req.status_code}{rst}.')
			return None

		try:
			search = yaml.load(req.text, Loader=yaml.FullLoader)
		except:
			error('Failed to get {bblue}ZoomEye{rst}/{byellow}{address}{rst}: failed to parse data.')
			return None

		if 'matches' not in search or len(search['matches']) == 0:
			error('Failed to get {bblue}ZoomEye{rst}/{byellow}{address}{rst}: no results.')
			return None

		host_token = None
		web_token  = None
		for match in search['matches']:
			if address not in match['ip']:
				continue

			if host_token is None and match['type'] == 'host':
				host_token = match['token']
			
			elif web_token is None and match['type'] == 'web':
				web_token = match['token']

		if web_token is None and host_token is None:
			error('Failed to get {bblue}ZoomEye{rst}/{byellow}{address}{rst}: failed to find tokens in results.')
			return None

		token = host_token if host_token is not None else web_token
		type  = 'host' if host_token is not None else 'web'
	
		headers['Referer'] = 'https://www.zoomeye.org/searchDetail?type=' + type + '&title=' + token

		params = (
			('from', 'detail'),
		)

		req = requests.get('https://www.zoomeye.org/' + type + '/details/' + token, headers=headers, params=params)
		if req.status_code != 200:
			error('Failed to get {bblue}ZoomEye{rst}/{byellow}{address}{rst}: status code is {bred}{req.status_code}{rst}.')
			return None
		
		data = None
		try:
			data = yaml.load(req.text, Loader=yaml.FullLoader)
		except:
			error('Failed to get {bblue}ZoomEye{rst}/{byellow}{address}{rst}: failed to parse data.')
			return None

		return data

	def enum(self, data):
		for svc in data['ports']:
			info('Discovered service {bgreen}{svc[service]}{rst} on port {bgreen}{svc[port]}{rst}/{bgreen}{transport}{rst}.',
				transport=svc['transport'] or 'tcp')


class LeakIXWeb(WebBase):
	def name(self):
		return "LeakIX"

	def get(self, address):
		headers = {
			'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
			'cookie': self.config('cookies'),
			'referer': 'https://leakix.net/search?scope=service&q=' + address,
			'authority': 'leakix.net',
			'pragma': 'no-cache',
			'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
			'accept-language': 'en-US,en;q=0.9',
			'cache-control': 'no-cache',
			'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'sec-fetch-site': 'same-origin',
			'sec-fetch-mode': 'navigate',
			'sec-fetch-user': '?1',
			'sec-fetch-dest': 'document',
			'upgrade-insecure-requests': '1'
		}

		req = requests.get('https://leakix.net/host/' + address, headers=headers)
		if req.status_code != 200:
			error('Failed to get {bblue}LeakIX{rst}/{byellow}{address}{rst}: status code is {bred}{req.status_code}{rst}.')
			return None

		tree = etree.HTML(req.text)
		svcs = tree.xpath('//ul[@id="service-panel"]/li')

		# enumerate services tab with ports + banners

		ports = {}
		
		for svc in svcs:
			port = svc.xpath('.//a[starts-with(@href, "/host")]/text()')

			if len(port) > 0:
				port = port[0].split(':')[-1]
			else:
				continue

			banner = svc.xpath('.//pre')
			if len(banner) > 0:
				banner = banner[0].text
			else:
				banner = None

			if port not in ports or not ports[port]:
				ports[port] = banner

		# enumerate software list

		data = []

		softs = tree.xpath('//div[h5[contains(text(), "Software information")]]//div[contains(@class, "list-group-item")]')
		for soft in softs:
			prod = soft.xpath('./p[@class="h5"]/small')
			version = None
			if len(prod) > 0:
				version = prod[0].text
				prod = prod[0].xpath('./preceding-sibling::text()')[-1].strip()
			else:
				prod = None

			svcs = soft.xpath('.//span[contains(@class, "badge")]/text()')
			for svc in svcs:
				svc = svc.split('/')
				
				data.append({
					'port': svc[1],
					'transport': svc[0],
					'product': prod,
					'version': version,
					'banner': ports[svc[1]] if svc[1] in ports else None
				})

		# check if anything is missing

		if len(data) == 0 and len(ports) == 0:
			error('Failed to get {bblue}LeakIX{rst}/{byellow}{address}{rst}: no services found.')
			return None

		for svc in data:
			if svc['port'] in ports:
				del ports[svc['port']]

		for port in ports:
			data.append({
				'port': port,
				'transport': 'tcp',
				'product': None,
				'version': None,
				'banner': ports[port]
			})

		return data

	def enum(self, data):
		for svc in data:
			info('Discovered service {bgreen}{svc[transport]}{rst} on port {bgreen}{svc[port]}{rst}/{bgreen}{svc[transport]}{rst}.')


class PassiveScanner:
	verbose = 0
	outdir  = ''

	def write_result(self, address, service, data):
		with open(os.path.join(self.outdir, address, service + '.json'), 'w') as f:
			f.write(json.dumps(data, indent=4, sort_keys=True))


	def read_result(self, address, service):
		with open(os.path.join(self.outdir, address, service + '.json'), 'r') as f:
			return json.load(f)


	def has_cached_result(self, address, service):
		file = os.path.join(self.outdir, address, service + '.json')
		return os.path.isfile(file) and (datetime.datetime.today() - datetime.datetime.fromtimestamp(os.path.getmtime(file))).days < 1


	def scan_host(self, address):
		info('Getting passive scan data for host {byellow}{address}{rst}...')
		basedir = os.path.join(self.outdir, address)
		os.makedirs(basedir, exist_ok=True)

		scanners = [ShodanWeb(), CensysWeb(), ZoomEyeWeb(), LeakIXWeb()]

		for scanner in scanners:
			name   = scanner.name()
			cache  = name.lower()
			result = None

			if self.has_cached_result(address, cache):
				if self.verbose >= 1:
					debug('Returning {bblue}{name}{rst}/{byellow}{address}{rst} from recent cache.')

				result = self.read_result(address, cache)

			if result is None:
				if self.verbose >= 1:
					debug('Getting fresh {bblue}{name}{rst}/{byellow}{address}{rst} data...')

				result = scanner.get(address)
				if result is not None:
					self.write_result(address, cache, result)

			if result is None:
				error('Failed to get passive scan data for {byellow}{address}{rst}.')
				continue

			scanner.enum(result)


if __name__ == '__main__':
	s = PassiveScanner()

	parser = argparse.ArgumentParser(description='Passive network reconnaissance tool for enumerating a host.')
	parser.add_argument('address', action='store', help='address of the host.')
	parser.add_argument('-o', '--output', action='store', default='results', help='output directory for the results')
	parser.add_argument('-v', '--verbose', action='count', help='enable verbose output, repeat for more verbosity')
	parser.error = lambda x: fail(x[0].upper() + x[1:])
	args = parser.parse_args()

	s.outdir  = args.output
	s.verbose = args.verbose if args.verbose is not None else 0

	s.scan_host(args.address)

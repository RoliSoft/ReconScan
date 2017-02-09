# ReconScan

The purpose of this project is to develop scripts that can be useful in the pentesting workflow, be it for VulnHub VMs, CTFs, hands-on certificates, or real-world targets.

The project currently consists of two major components: a script invoking and aggregating the results of existing tools, and a second script for automated analysis of the aforementioned results from the perspective of exploitability.

In terms of real-world pentesting, these scripts are not meant to replace commercial tools such as Nessus or Nexpose, but they can complement it nicely for finding the latest vulnerabilities and their PoC exploits.

## Network reconnaissance

The `recon.py` script runs various open-source tools in order to enumerate the services on a host. Best run under Kali Linux or similar pentesting-oriented distribution with these tools preinstalled and preconfigured.

The flow followed by the script is as follows:

- Scan all TCP/UDP ports with nmap, service detection, minimal amount of scripts:
	- If there are unidentified services, try amap.
	- For identified software, run vulnerability analysis with `vulnscan.py`
	- For identified services, run further analysis:
		- HTTP(S): nmap with all http scripts, nikto, dirb
		- SMTP: nmap with all smtp scripts
		- FTP: nmap with all ftp scripts, hydra if requested
		- SMB: nmap with all smb scripts, enum4linux, samrdump
		- MSSQL: nmap with all mssql scripts
		- SSH: hydra if requested
		- SNMP: onesixtyone, snmpwalk
		- DNS: attempt zone transfer (axfr) with dig

Results will be dumped into the `results/$ip_address` directory, with the `$port_$service_$tool` file naming scheme. The tools are mostly run simultaneously (unless one depends on the result of another) and the CLI output will be aggregated and tagged by the script, so you will see the progress and dirt found by each running script in real-time.

### Usage

	usage: recon.py [-h] [-b] [-n] [-v] [-o OUTPUT] address [port] [service]
	
	positional arguments:
	  address               address of the host.
	  port                  port of the service, if scanning only one port
	  service               type of the service, when port is specified
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -b, --bruteforce      bruteforce credentials with hydra
	  -n, --dry-run         does not invoke commands
	  -v, --verbose         enable verbose output, repeat for more verbosity
	  -o OUTPUT, --output OUTPUT
							output directory for the results

### Origin

This script is inspired by [Mike Czumak's Recon Scan](http://www.securitysift.com/offsec-pwb-oscp/), which he wrote during his OSCP exam. Many modifications can be found on GitHub, however, I wanted to write a script from scratch, familiarizing myself with each tool and their parameterization, instead of just reusing a bunch of scripts found scattered in various repositories, leaving me none the wiser.

## Vulnerability analysis

The `vulnscan.py` script analyses a specified CPE name to determine whether it has any known vulnerabilities and published exploits.

As input, it takes a CPE name, a full name and version, or a path to an xml-based nmap report, which was generated with service detection. When not providing a CPE name, the free-text provided will be fuzzy-matched with the CPE dictionary to check if the provided software name and version has a CPE name. When an nmap report is provided, the CPE names for the identified services are used for the lookup. If the software name and version is available, but the CPE name is not, it will try to fuzzy-match it.

Based on my previous experiences, directly looking up the affected software entries in the CVE database does not always yield the most accurate results, as a software might have multiple CPE names, all referring to the same software. For example, `nginx` might be listed as `cpe:/a:nginx:nginx` or `cpe:/a:igor_sysoev:nginx`, and on the more extreme side, `X11` has 12 CPE aliases. In order to combat this, a CPE alias list is used, which is provided and maintained by the Debian Security team, and all aliases are looked up for a given CPE name. Using this technique tends to generate much better results.

Vulnerabilites are listed and color-coded based on availability: gray - no public known exploit, yellow - partially public or limited information, red - public exploit available.

In order to take it one step further, the ExploitDB and SecurityFocus references are extracted from the CVE entries, which allows the script to provide direct links to the exploits. In order to provide perfect ExploitDB and SecurityFocus results for the vulnerabilities, curated lists will have to be used during database updates. If these lists are missing, ExploitDB and SecurityFocus links will still be displayed, but with issues: the SecurityFocus IDs are listed, but information is not available in the CVE entries themselves on whether the SecurityFocus exploit page has any content or not; similarly, the ExploitDB references seem to be missing quite a few entries.

The curated list for ExploitDB should be placed under `nvd/exploitdb.lst`, which will act as a supplemental EDB-CVE map to the ones found in the CVE references. The SecurityFocus list should be placed under `nvd/securityfocus.lst`, which is a list of SecurityFocus IDs with exploit entries, and this list will be used to determine whether a SecurityFocus CVE reference will be imported or not.

### Usage

	usage: vulnscan.py [-h] [-a] [-e] [-u] [query]
	
	positional arguments:
	  query           CPE name, full name and version to fuzzy match, or path to nmap report (generated with -sV)
	
	optional arguments:
	  -h, --help      show this help message and exit
	  -a, --all       dump all vulnerabilities for a CPE when no version is included (off by default)
	  -e, --exploits  dump only vulnerabilities with public exploits available
	  -u, --update    download the CVE dumps and recreate the local database

### Origin

The idea for this comes from my other open-source project, [Host Scanner](https://github.com/RoliSoft/Host-Scanner), which does exactly this, but is written in C++ and is focused more towards security researchers and system administrators, as opposed to CTF players.

The C++ version has a slightly different feature set compared to this Python version: while the main goal of the Python version is to parse nmap reports and end up at exploit links, the C++ version has its own active and passive network scanner, service identifier, and researcher-oriented features, such as non-intrusive vulnerability validation through package manager changelog reports.

## Licensing

Copyright (c) `2017` `RoliSoft <root@rolisoft.net>`

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed in the hope that it will be useful, but without any warranty; without even the implied warranty of merchantability or fitness for a particular purpose.

For more information regarding the terms and conditions of this software, please read the full legal text of the GNU General Public License version 3, a copy of which is available in the [LICENSE.md](LICENSE.md) file. Otherwise, see &lt;<http://www.gnu.org/licenses/>&gt;.

Some of the invoked tools are licensed under GPL or a form of GPL-derived license with added clauses further restricting how data produced by the tool can be processed, e.g. nmap.
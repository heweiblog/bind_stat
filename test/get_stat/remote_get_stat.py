#!/usr/bin/python3
#-*- coding: utf-8 -*-

import requests,re,json
import xml.etree.ElementTree as ElementTree

def get_named_stat(ip):
	try:
		r = requests.get('http://{}:8053/'.format(ip))
		print(r)
		root = ElementTree.fromstring(r.text)
		print(root)
		if root.tag == 'isc':
			version = root.find('./bind/statistics').attrib['version']
		elif root.tag == 'statistics':
			version = root.attrib['version']
		else:
			print("Unknown root tag: {}".format(root.ag), file=sys.stderr)

		v = re.match('^(\d{1})\.', version)
		version = int(v.group(1))
		print(version)
		if version < 0 or version > 3:
			print("Unsupported bind statistics version: {}".format(root.attrib), file=sys.stderr)

		j = { 
				'zones': {}, 
				'counter': {}, 
				'zonemaintenancecounter': {}, 
				'resolvercounter': {}, 
				'socketcounter': {}, 
				'incounter': {}, 
				'outcounter': {}, 
				'cache': {}, 
				'memory': {}
		}

		if version == 2:
			for view in root.iterfind('./bind/statistics/views/view'):
				if view.findtext('./name') in ('_default',):
					for zone in view.iterfind('./zones/zone'):
						if zone.find('./counters') is not None:
							counters = {}
							for counter in zone.iterfind('./counters/*'):
								counters[counter.tag] = counter.text
							j['zones'][zone.findtext('./name')] = counters
			for stat in root.iterfind('./bind/statistics/server/nsstat'):
				j['counter'][stat.findtext('./name')] = stat.findtext('./counter')
			for stat in root.iterfind('./bind/statistics/server/zonestat'):
				j['zonemaintenancecounter'][stat.findtext('./name')] = stat.findtext('./counter')
			for view in root.iterfind('./bind/statistics/views/view'):
				if view.findtext('./name') in ('_default',):
					for stat in view.iterfind('./resstat'):
						j['resolvercounter'][stat.findtext('./name')] = stat.findtext('./counter')
			for stat in root.iterfind('./bind/statistics/server/sockstat'):
				j['socketcounter'][stat.findtext('./name')] = stat.findtext('./counter')
			for stat in root.iterfind('./bind/statistics/server/queries-in/rdtype'):
				j['incounter'][stat.findtext('./name')] = stat.findtext('./counter')
			for stat in root.iterfind('./bind/statistics/views/view/rdtype'):
				j['outcounter'][stat.findtext('./name')] = stat.findtext('./counter')
			# Memory
			for child in root.iterfind('./bind/statistics/memory/summary/*'):
				j['memory'][child.tag] = child.text
			# Cache for local
			for child in root.iterfind('./bind/statistics/views/view/cache'):
				if child.attrib['name'] == 'localhost_resolver':
					for stat in child.iterfind('./rrset'):
						j['cache'][stat.findtext('./name')] = stat.findtext('./counter')

			# this is for newer version 3
			if version == 3:
				for child in root.iterfind('./server/counters'):
					# V2 ./bind/statistics/server/nsstat
					if child.attrib['type'] == 'nsstat':
						for stat in child.iterfind('./counter'):
							j['counter'][stat.attrib['name']] = stat.text
					# V2 ./bind/statistics/server/sockstat
					if child.attrib['type'] == 'sockstat':
						for stat in child.iterfind('./counter'):
							j['socketcounter'][stat.attrib['name']] = stat.text
					# V2 ./bind/statistics/server/zonestat
					if child.attrib['type'] == 'zonestat':
						for stat in child.iterfind('./counter'):
							j['zonemaintenancecounter'][stat.attrib['name']] = stat.text
					# V2 ./bind/statistics/server/queries-in/rdtype
					if child.attrib['type'] == 'qtype':
						for stat in child.iterfind('./counter'):
							j['incounter'][stat.attrib['name']] = stat.text
				# they are only for block _default
				for child in root.iterfind('./views/view/counters'):
					# V2 ./bind/statistics/views/view/rdtype
					if child.attrib['type'] == 'resqtype':
						for stat in child.iterfind('./counter'):
							j['outcounter'][stat.attrib['name']] = stat.text
					# V2 ./bind/statistics/views/view => _default name only
					if child.attrib['type'] == 'resstats':
						for stat in child.iterfind('./counter'):
							j['resolvercounter'][stat.attrib['name']] = stat.text
					# V2: no (only in memory detail stats)
					if child.attrib['type'] == 'cachestats':
						for stat in child.iterfind('./counter'):
							j['cache'][stat.attrib['name']] = stat.text
				# V2 has @name = localhost_resolver, interal, external
				for child in root.iterfind('./views/view/cache'):
					if (child.attrib['name'] == '_default'):
						for stat in child.iterfind('./rrset'):
							j['cache'][stat.findtext('./name')] = stat.findtext('./counter')
							# for sets stating with !, we replace that with an _ (! is not allowed in zabbix)
							if re.match('^!', stat.findtext('./name')):
								j['cache'][stat.findtext('./name').replace('!', '_')] = stat.findtext('./counter')
				# for all the Zone stats only
				for child in root.iterfind('./views/view'):
					# only for default
					if (child.attrib['name'] == '_default'):
						# V2 ./bind/statistics/views/view -> ./zones/zone => _default name only
						for zone in child.iterfind('./zones/zone'):
							counters = {}
							for stat in zone.iterfind('./counters'):
								if stat.attrib['type'] == 'rcode' or stat.attrib['type'] == 'qtype':
									for counter in stat.iterfind('./counter'):
										counters[counter.attrib['name']] = counter.text
							j['zones'][zone.attrib['name']] = counters
				# V2 ./bind/statistics/memory/summary/*
				for child in root.iterfind('./memory/summary/*'):
					j['memory'][child.tag] = child.text

			# write to cache is the same in both version
			print(j)
			with open('stat.txt', 'w') as f:
				json.dump(j, f)


	except Exception as e:
		print('get data from stat file error:'+str(e))

get_named_stat('192.168.6.104')





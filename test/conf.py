# -*- coding: utf-8 -*-

from ConfigParser import ConfigParser, NoSectionError, NoOptionError
import sys

Conf = {}

try:
	config = ConfigParser()
	config.read('./etc/drmsd.ini')

	network = {}
	network['port'] = config.getint('network', 'port')
	network['ackhost'] = config.get('network', 'ackhost')
	network['ackport'] = config.getint('network', 'ackport')
	Conf['network'] = network

	security = {}
	security['gPwd'] = config.get('security', 'secret')
	security['gAESKey'] = config.get('security', 'aes_key')
	security['gAESIV'] = config.get('security', 'aes_iv')
	Conf['security'] = security

	named = {}
	named['home'] = config.get('named-conf', 'home')
	named['switch'] = config.get('named-conf', 'switch')
	named['std'] = config.get('named-conf', 'std')
	named['local'] = config.get('named-conf', 'local')
	Conf['named-conf'] = named

	source ={}
	source['root_source'] = config.get('source', 'root_source')
	source['standard_source'] = config.get('source', 'standard_source')
	source['exigency_source'] = config.get('source', 'exigency_source')
	Conf['source'] = source

except (NoSectionError, NoOptionError):
	print('config file /etc/drmsd.ini missing session or value')
	sys.exit(1)


#print(Conf)

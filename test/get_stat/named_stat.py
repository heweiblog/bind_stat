#!/usr/bin/python3
#-*- coding: utf-8 -*-

import requests,lxml.etree,xmltodict,os,json

def get_named_stat(ip):
	try:
		r = requests.get('http://{}:8053/'.format(ip))
		#ele = lxml.etree.fromstring(r.text.encode('utf-8'))
		print(type(r.text))
		dic = xmltodict.parse(r.text, encoding='utf-8')
		print(type(dic))
		#dic = json.dumps(dic, indent=4)
		#print(dic)
		#di = json.dumps(dic['statistics']['server']['counters'], indent=4)
		#print(di)
		query,serverfail,response,answer,request_ipv4,request_ipv6 = 0,0,0,0,0,0
		data = dic['statistics']['server']['counters']
		for d in data:
			for i in d:
				if i == '@type' and d['@type'] == 'opcode':
					#print(i)
					for j in d['counter']:
						for k in j:
							#print(k)
							if '@name' == k and j['@name'] == 'QUERY':
								query = int(j['#text'])
				elif i == '@type' and d['@type'] == 'rcode':
					for j in d['counter']:
						for k in j:
							#print(k)
							if '@name' == k and j['@name'] == 'SERVFAIL':
								serverfail = int(j['#text'])
							if '#text' == k:
								response += int(j['#text'])
				elif i == '@type' and d['@type'] == 'nsstat':
					for j in d['counter']:
						for k in j:
							#print(k)
							if '@name' == k and j['@name'] == 'Requestv4':
								request_ipv4 = int(j['#text'])
							if '@name' == k and j['@name'] == 'Requestv6':
								request_ipv6 = int(j['#text'])
							if '@name' == k and j['@name'] == 'Response':
								answer = int(j['#text'])
				else:
					continue
                    
		print(query,serverfail,response,request_ipv4,request_ipv6,answer)
		#print(data)
		#print(dic['statistics']['server']['counters'])
		#ele = lxml.etree.fromstring(r.text.encode('utf-8'))
		#res = ele.xpath('QUERY')
		#res = ele.xpath('statistics')
		#if res and res[0].text:
			#data = res[0].text
			#print(data)

	except Exception as e:
		print('get data from stat file error:'+str(e))

get_named_stat('192.168.6.104')

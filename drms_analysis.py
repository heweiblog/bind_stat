#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os, sys, time, datetime, logging, string, logging.handlers, gzip, paramiko
import multiprocessing,socket
from configparser import ConfigParser

import zlib, json, dns, dns.resolver
import requests, xmltodict, threading

import daemon

def upload_to_ftp(file_name,data_type):
	global ftp_ip, ftp_port, ftp_user, ftp_pwd, ftp_dir, logger

	try:
		transport = paramiko.Transport((ftp_ip, ftp_port))
		transport.connect(username = ftp_user, password = ftp_pwd)
		sftp = paramiko.SFTPClient.from_transport(transport)
		listdir = sftp.listdir('/')
		if ftp_dir not in listdir:
			sftp.mkdir(ftp_dir)
			logger.error('ftp upload dir not exit and create')
		sftp.chdir(ftp_dir)
		listdir = sftp.listdir('.')
		if data_type not in listdir:
			sftp.mkdir(data_type)
		sftp.chdir(data_type)
		listdir = sftp.listdir('.')
		data_dir = time.strftime('%Y-%m-%d')
		if data_dir not in listdir:
			sftp.mkdir(data_dir)
		sftp.chdir(data_dir)
		sftp.put('/tmp/'+file_name,file_name)
		sftp.close()
		transport.close()
	
	except Exception as e:
		logger.error('upload to sftp error:'+str(e))
		return False

	logger.info('upload file %s success' % file_name)
	return True


def get_top10_and_delay(server):
	global logger, file_port
	target_file = '/tmp/'+server['id']+'.txt'
	try:
		with open(target_file,'w') as f:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((server['ip'], file_port))
			s.send('root_copy_resolve_data'.encode())
			while True:
				d = s.recv(1024)
				if d:
					f.write(d.decode('utf-8'))
				else:
					break
			s.close()
	except Exception as e:
		logger.error('get root_copy remote dnstap file error:'+str(e))
		return [],0 

	top,request,respond = {},{},{}

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
				if l[5].split(':')[-1] == '53':
					if '->' in l:
						k = l[3]+l[5]+l[-1]
						request[k] = int(1000*float(l[1].split(':')[-1]))
					elif '<-' in l:
						k = l[3]+l[5]+l[-1]
						respond[k] = int(1000*float(l[1].split(':')[-1]))
						dname = l[-1].split('/')[0].split('.')
						if len(dname) > 1 and dname[-1].islower():
							domain = dname[-1]
							if domain in top:
								top[domain] += 1
							else:
								top[domain] = 1
	
		vals = list(top.values())
		vals.sort(reverse = True)

		if len(vals) > 10:
			vals = vals[:10]
	
		new_vals = []
		for i in vals:
			if i not in new_vals:
				new_vals.append(i)
	
		top10 = []
		for val in new_vals:
			k = [k for k, v in top.items() if v == val]
			for s in k:
				top10.append(s)

		total,count,avg_delay = 0,0,0
		for k in respond:
			if k in request:
				delay = respond[k] - request[k]
				if delay < 0:
					delay = 60000 - request[k] + respond[k]
				count += 1
				total += delay
		if count != 0:
			avg_delay = total//count
		return top10,avg_delay

	except Exception as e:
		logger.error('get top10 and delay error'+str(e))

	return [],0 



def get_named_stat(ip):
	global stat_port, logger
	try:
		r = requests.get('http://{}:{}/'.format(ip,stat_port))
		dic = xmltodict.parse(r.text, encoding='utf-8')
		query,serverfail,response,request_ipv4,request_ipv6 = 0,0,0,0,0
		data = dic['statistics']['server']['counters']
		for d in data:
			for i in d:
				if i == '@type' and d['@type'] == 'opcode':
					for j in d['counter']:
						for k in j:
							if '@name' == k and j['@name'] == 'QUERY':
								query = int(j['#text'])
				elif i == '@type' and d['@type'] == 'rcode':
					for j in d['counter']:
						for k in j:
							if '@name' == k and j['@name'] == 'SERVFAIL':
								serverfail = int(j['#text'])
							if '#text' == k:
								response += int(j['#text'])
				elif i == '@type' and d['@type'] == 'nsstat':
					for j in d['counter']:
						for k in j:
							if '@name' == k and j['@name'] == 'Requestv4':
								request_ipv4 = int(j['#text'])
							if '@name' == k and j['@name'] == 'Requestv6':
								request_ipv6 = int(j['#text'])
							#if '@name' == k and j['@name'] == 'Response':
								#answer = int(j['#text'])
				else:
					continue
		return query,serverfail,response,request_ipv4,request_ipv6

	except Exception as e:
		logger.warning('get data from stat file error:'+str(e))
	
	return 0,0,0,0,0


def get_real_named_stat(fname,ip):
	data = {}
	try:
		with open(fname,'r') as f:
			data = json.load(f)
	except Exception as e:
		logger.warning('first or file bad:'+str(e))
		return 0,0,0,0,0

	querys,serverfail,response,request_ipv4,request_ipv6 = get_named_stat(ip)
	back_data = {
		'querys' : querys,
		'serverfail' : serverfail,
		'response' : response,
		'request_ipv4' : request_ipv4,
		'request_ipv6' : request_ipv6
	}

	with open(fname,'w') as f:
		json.dump(back_data, f, sort_keys=True, indent=4, separators=(',', ': '))
	
	querys = querys - data['querys'] if data['querys'] else 0
	serverfail = serverfail - data['serverfail'] if data['serverfail'] else 0
	response = response - data['response'] if data['response'] else 0
	request_ipv4 = request_ipv4 - data['request_ipv4'] if data['request_ipv4'] else 0
	request_ipv6 = request_ipv6 - data['request_ipv6'] if data['request_ipv6'] else 0

	return querys,serverfail,response,request_ipv4,request_ipv6


def get_root_copy_analysis_data(server):
	global node_id, upload_delay, logger
	fname = '/tmp/root_copy_'+server['id']+'.json'

	querys,serverfail,response,request_ipv4,request_ipv6 = get_real_named_stat(fname,server['ip'])
	top,delay = get_top10_and_delay(server)

	root_copy_resolve_data = {
		'type':'root_copy',
		'data' : {
			'id': node_id,
			'server-id': server['id'],
			'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'qps': querys//upload_delay,
			'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'delay': delay,
			'resolution-count': response,
			'response-success-rate': 0 if querys == 0 else response*100//querys,
			'resolution-success-rate': 0 if querys == 0 else (response-serverfail)*100//querys,
			'top10': top
		}
	}

	return root_copy_resolve_data	


def get_root_copy_list(ip):
	global local, home, file_port, logger
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip, file_port))
		s.send('recursion_root_copy_list'.encode())
		d = s.recv(1024)
		s.close()
		if d:
			return d.decode('utf-8').split(',')
	except Exception as e:
		logger.error('get root copy list error:'+str(e))
	return []


def get_recursion_root_stat(server):
	global logger, file_port
	target_file = '/tmp/'+server['id']+'.txt'
	root_copy_list = get_root_copy_list(server['ip'])
	root_ip_list = [
		'202.12.27.33',
		'2001:dc3::35',
		'199.9.14.201',
		'2001:500:200::b',
		'192.33.4.12',
		'2001:500:2::c',
		'199.7.91.13',
		'2001:500:2d::d',
		'192.203.230.10',
		'2001:500:a8::e',
		'192.5.5.241',
		'2001:500:2f::f',
		'192.112.36.4',
		'2001:500:12::d0d',
		'198.97.190.53',
		'2001:500:1::53',
		'198.41.0.4',
		'2001:503:ba3e::2:30',
		'192.36.148.17',
		'2001:7fe::53',
		'192.58.128.30',
		'2001:503:c27::2:30',
		'193.0.14.129',
		'2001:7fd::1',
		'199.7.83.42',
		'2001:500:9f::42'
	] + root_copy_list 

	root_list = {
		'm': ['202.12.27.33','2001:dc3::35'],
		'b': ['199.9.14.201','2001:500:200::b'],
		'c': ['192.33.4.12','2001:500:2::c'],
		'd': ['199.7.91.13','2001:500:2d::d'],
		'e': ['192.203.230.10','2001:500:a8::e'],
		'f': ['192.5.5.241','2001:500:2f::f'],
		'g': ['192.112.36.4','2001:500:12::d0d'],
		'h': ['198.97.190.53','2001:500:1::53'],
		'a': ['198.41.0.4','2001:503:ba3e::2:30'],
		'i': ['192.36.148.17','2001:7fe::53'],
		'j': ['192.58.128.30','2001:503:c27::2:30'],
		'k': ['193.0.14.129','2001:7fd::1'],
		'l': ['199.7.83.42','2001:500:9f::42'],
		'root_copy': root_copy_list
	}

	root_stat = {'a':0, 'b':0, 'c':0, 'd':0, 'e':0, 'f':0, 'g':0, 'h':0, 'i':0, 'j':0, 'k':0, 'l':0, 'm':0, 'root_copy':0}
	delay_stat = root_stat.copy()

	try:
		with open(target_file,'w') as f:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((server['ip'], file_port))
			s.send('recursion_resolve_data'.encode())
			while True:
				d = s.recv(1024)
				if d:
					f.write(d.decode('utf-8'))
				else:
					break
			s.close()
	except Exception as e:
		logger.error('get recursion remote dnstap file error:'+str(e))
		del root_stat['root_copy']
		del delay_stat['root_copy']
		return root_stat,0,0,delay_stat,0 

	root,request,respond = {},{},{}

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
				if l[5].split(':')[-1] == '53':
				#after add root 13 delay stat
					if '->' in l:
						k = l[3]+l[5]+l[-1]
						request[k] = int(1000*float(l[1].split(':')[-1]))
					elif '<-' in l:
						k = l[3]+l[5]+l[-1]
						respond[k] = int(1000*float(l[1].split(':')[-1]))
						domain = l[5].split(':53')[0]
						if domain in root_ip_list:
							if domain in root:
								root[domain] += 1
							else:
								root[domain] = 1

		for k in root_list:
			for ip in root_list[k]:
				if ip in root:
					root_stat[k] += root[ip]
				
		total,count,avg_delay = 0,0,0
		for k in respond:
			if k in request:
				delay = respond[k] - request[k]
				if delay < 0:
					delay = 60000 - request[k] + respond[k]
				count += 1
				total += delay

		if count != 0:
			avg_delay = total//count

		dns_query = dns.message.make_query('.', 'NS')
		for k in root_list:
			if root_stat[k] > 0 and len(root_list[k]) > 0: 
				try:
					begin = datetime.datetime.now()
					response = dns.query.udp(dns_query, root_list[k][0], port = 53,timeout = 2)
					end = datetime.datetime.now()
					delay_stat[k] = (end - begin).microseconds//1000
				except Exception as e:
					logger.warning(k+' get root delay error:'+str(e))

		root_copy_cnt = root_stat['root_copy']
		root_copy_delay = delay_stat['root_copy']
		del root_stat['root_copy']
		del delay_stat['root_copy']
		return root_stat,avg_delay,root_copy_cnt,delay_stat,root_copy_delay

	except Exception as e:
		logger.warning('get recursion root 13 stat error:'+str(e))

	del root_stat['root_copy']
	del delay_stat['root_copy']
	return root_stat,0,0,delay_stat,0 




def get_recursion_analysis_data(server):
	global node_id, upload_delay, logger
	fname = '/tmp/recursion_'+server['id']+'.json'

	querys,serverfail,response,request_ipv4,request_ipv6 = get_real_named_stat(fname,server['ip'])
	root_count_dict,delay,root_copy_count,root_delay_dict,root_copy_delay = get_recursion_root_stat(server)

	recursion_resolve_data = {
		'type' : 'recursion',
		'data' : {
			'id': node_id,
			'server-id': server['id'],
			'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'delay': delay,
			'qps': querys//upload_delay,
			'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'resolution-count-v4': request_ipv4,
			'resolution-count-v6': request_ipv6,
			'response-success-rate': 0 if querys == 0 else response*100//querys,
			'resolution-success-rate': 0 if querys == 0 else (response - serverfail)*100//querys,
			'query-7706-count': root_copy_count, 
			'query-7706-delay': root_copy_delay,
			'query-root-count': root_count_dict,
			'query-root-delay': root_delay_dict
		}
	}
	return recursion_resolve_data


def upload_root_copy_run_data(server,run_data):
	global operator, vendor, node_id, upload_delay, logger
	
	root_soa_data = {
		'operator': operator,
		'vendor' : vendor,
		'timestamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
		'data' : {
			'id': node_id,
			'server-id': server['id'],
			'ip': run_data['ip'],
			'source': run_data['source'],
			'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'result': run_data['result'],
			'size': run_data['size'],
			'soa': run_data['soa'],
			'delay': run_data['delay']
		}
	}

	logger.info(root_soa_data)

	file_name = 'zoneOperation' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	try:
		with gzip.open('/tmp/' + file_name, "wb") as f:
			data = json.dumps(root_soa_data,ensure_ascii=False,indent=4)
			f.write(bytes(data, 'utf-8'))
		upload_to_ftp(file_name,'15')
		os.remove('/tmp/' + file_name)
	except Exception as e:
		logger.error('upload root_copy run data error:'+str(e))


def get_root_copy_soa(ip):
	global logger
	try:
		dns_query = dns.message.make_query('.', 'SOA')
		res = dns.query.udp(dns_query, ip, port = 53,timeout = 2)
		for i in res.answer:
			for j in i.items:
				return j.serial
	except Exception as e:
		logger.warning('get root copy soa error:'+str(e))
	return 0


def get_root_copy_run_data(ip):
	global file_port
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip, file_port))
		s.send('root_copy_run_data'.encode())
		d = s.recv(1024)
		s.close()
		if d:
			return json.loads(d.decode('utf-8'))
	except Exception as e:
		logger.warning('get remote root copy run data error:'+str(e))
	return None


def get_data(server):
	global server_list
	if server['type'] == 'root_copy':
		soa = get_root_copy_soa(server['ip'])
		if soa != 0 and server['soa'] != soa:
			run_data = get_root_copy_run_data(server['ip'])
			if run_data:
				server['soa'] = run_data['soa']
				logger.info(server_list)
				upload_root_copy_run_data(server,run_data)
		return get_root_copy_analysis_data(server)
	elif server['type'] == 'recursion': 
		return get_recursion_analysis_data(server)
	return None


class MyThread(threading.Thread):

	def __init__(self,func,args=()):
		super(MyThread,self).__init__()
		self.func = func
		self.args = args

	def run(self):
		self.result = self.func(*self.args)

	def get_result(self):
		try:
			return self.result
		except Exception:
			return None


def get_first_data(server,fname):
	querys,serverfail,response,request_ipv4,request_ipv6 = get_named_stat(server['ip'])
	data = {
		'querys' : querys,
		'serverfail' : serverfail,
		'response' : response,
		'request_ipv4' : request_ipv4,
		'request_ipv6' : request_ipv6
	}
	with open(fname,'w') as f:
		json.dump(data, f, sort_keys=True, indent=4, separators=(',', ': '))


def upload_task():
	global server_list, upload_delay, operator, vendor, logger
	for server in server_list:
		if server['type'] == 'root_copy':
			fname = '/tmp/root_copy_'+server['id']+'.json'
			get_first_data(server,fname)
			run_data = get_root_copy_run_data(server['ip'])
			if run_data:
				server['soa'] = run_data['soa']
				upload_root_copy_run_data(server,run_data)
		elif server['type'] == 'recursion':
			fname = '/tmp/recursion_'+server['id']+'.json'
			get_first_data(server,fname)


	while True:
		time.sleep(upload_delay)
		threads = []
		for server in server_list:
			t = MyThread(get_data, args=(server,))
			threads.append(t)
			t.start()
		for t in threads:
			t.join()
		root_copy_resolve_data = {
			'operator': operator,
			'vendor' : vendor,
			'timestamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
			'data':[]
		}
		recursion_resolve_data = {
			'operator': operator,
			'vendor' : vendor,
			'timestamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
			'data' : []
		}
		for t in threads:
			data = t.get_result()
			if data:
				if data['type'] == 'root_copy':
					root_copy_resolve_data['data'].append(data['data'])
				elif data['type'] == 'recursion':
					recursion_resolve_data['data'].append(data['data'])
		try:
			if len(root_copy_resolve_data['data']) > 0:
				root_copy_file_name = 'zoneQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
				with gzip.open('/tmp/' + root_copy_file_name, "wb") as f:
					data = json.dumps(root_copy_resolve_data,ensure_ascii=False,indent=4)
					f.write(bytes(data, 'utf-8'))
				logger.info(root_copy_resolve_data)
				upload_to_ftp(root_copy_file_name,'16')
				os.remove('/tmp/' + root_copy_file_name)
			if len(recursion_resolve_data['data']) > 0:
				recursion_file_name = 'dnsQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
				with gzip.open('/tmp/' + recursion_file_name, "wb") as f:
					data = json.dumps(recursion_resolve_data,ensure_ascii=False,indent=4)
					f.write(bytes(data, 'utf-8'))
				logger.info(recursion_resolve_data)
				upload_to_ftp(recursion_file_name,'14')
				os.remove('/tmp/' + recursion_file_name)
		except Exception as e:
			logger.error('upload data error:'+str(e))



try:
	config = ConfigParser()
	config.read('/etc/drms_analysis.ini')

	ftp_ip = config.get('ftp', 'ip')
	ftp_port = config.getint('ftp', 'port')
	ftp_user = config.get('ftp', 'user')
	ftp_pwd = config.get('ftp', 'pwd')
	ftp_dir = config.get('ftp', 'dir')

	upload_delay = config.getint('server', 'upload_delay')
	operator = config.get('server', 'operator')
	vendor = config.get('server', 'vendor')
	node_id = config.get('server', 'node_id')
	stat_port = config.get('server', 'stat_port')
	file_port = config.getint('server', 'file_port')
	
	server_list=[]
	if config.has_section('root_copy'):
		cip = config.get('root_copy', 'ip')
		ciplist = cip.split(',')
		cid = config.get('root_copy', 'id')
		cidlist = cid.split(',')
		for i in range(len(ciplist)):
			root_copy={'type':'root_copy','soa':0}
			root_copy['ip'] = ciplist[i]
			root_copy['id'] = cidlist[i]
			server_list.append(root_copy)

	if config.has_section('recursion'):
		rip = config.get('recursion', 'ip')
		riplist = rip.split(',')
		rid = config.get('recursion', 'id')
		ridlist = rid.split(',')
		for i in range(len(riplist)):
			recursion={'type':'recursion'}
			recursion['ip'] = riplist[i]
			recursion['id'] = ridlist[i]
			server_list.append(recursion)

except Exception as e:
	print('load conf or create log error:'+str(e))
	sys.exit(1)


with daemon.DaemonContext():
	logger = logging.getLogger('drms_analysis')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/var/log/drms_analysis.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s - %(lineno)s - %(levelname)s - %(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('main process start at: %s' % time.ctime())

	while True:
		p1 = multiprocessing.Process(target = upload_task, args = ())
		p1.start()
		p1.join()

	logger.info('main process end at: %s' % time.ctime())



'''
logger = logging.getLogger('drms_analysis')
logger.setLevel(level = logging.INFO)
handler = logging.FileHandler("/var/log/drms_analysis.log")
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(lineno)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

logger.info('main process start at: %s' % time.ctime())
logger.info(server_list)

while True:
	p1 = multiprocessing.Process(target = upload_task, args = ())
	p1.start()
	p1.join()

logger.info('main process end at: %s' % time.ctime())
'''


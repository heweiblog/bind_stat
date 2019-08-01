
from configparser import ConfigParser

try:
	config = ConfigParser()
	config.read('etc/drms_analysis.ini')

	server_list=[]
	root_copy={'type':'root_copy'}
	cip = config.get('root_copy', 'ip')
	ciplist = cip.split(',')
	cid = config.get('root_copy', 'id')
	cidlist = cid.split(',')
	for i in range(len(ciplist)):
		root_copy['ip'] = ciplist[i]
		root_copy['id'] = cidlist[i]
		server_list.append(root_copy)

	recursion={'type':'recursion'}
	rip = config.get('recursion', 'ip')
	riplist = rip.split(',')
	rid = config.get('recursion', 'id')
	ridlist = rid.split(',')
	for i in range(len(riplist)):
		recursion['ip'] = riplist[i]
		recursion['id'] = ridlist[i]
		server_list.append(recursion)
	print(server_list)

except Exception as e:
	print('load conf or create log error:'+str(e))



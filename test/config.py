
from configparser import ConfigParser

try:
	config = ConfigParser()
	config.read('etc/drms_analysis.ini')

	ftp_ip = config.get('recursion', 'ip')
	print(type(ftp_ip))
	print(ftp_ip)
	print(ftp_ip.split(','))
	id = config.get('recursion', 'id')
	print(id.split(','))

except Exception as e:
	print('load conf or create log error:'+str(e))
	sys.exit(1)

#!/usr/bin/python3
#-*- coding: utf-8 -*-

import subprocess,os

def get_stat_file():
	home, rndc = 'etc','rndc'
	tmp_stat_file,stat_file = '/var/named/data/tmp_stats.txt','/var/named/data/named_stats.txt'

	try:
		subprocess.check_call(['rm', '-rf', stat_file], cwd = home)
		subprocess.check_call(['rm', '-rf', tmp_stat_file], cwd = home)
	except Exception as e:
		print('rm -rf stat file error:'+str(e))
		return False

	try:
		subprocess.check_call([rndc, 'stats'], cwd = home)
		os.rename(stat_file,tmp_stat_file)
	except Exception as e:
		print('rndc stats error:'+str(e))
		return False

	return True


get_stat_file()




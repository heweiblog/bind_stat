#-*- encoding: utf8 -*

import base64, hashlib, zlib
import os, sys
import json

from spyne import Application, rpc, ServiceBase, Iterable
from spyne.model.primitive import Int, Long, Integer, Unicode
from spyne.protocol.soap import Soap11
from spyne.server.wsgi import WsgiApplication
from spyne.util.wsgi_wrapper import WsgiMounter 
from wsgiref.simple_server import make_server
import xml.dom.minidom
from copy import deepcopy
import binascii
from Crypto.Cipher import AES 
import traceback
from time import sleep
import threading
import time
import random,string
import osa
import lxml.etree
from setproctitle import setproctitle,getproctitle

#from public import userPort,recursivePort,rootPort
from public import *


gPwd        = '1234567890abcDEF'
gAESKey     = b'1234567890abcDEF'
gAESIV      = b'1234567890abcDEF'

class AESCipher:
	def __init__(self, key, iv):
		self.key = key 
		self.iv = iv 
	def __pad(self, text):
		text_length = len(text)
		amount_to_pad = AES.block_size - (text_length % AES.block_size)
		if amount_to_pad == 0:
			amount_to_pad = AES.block_size
		pad = chr(amount_to_pad)
		return text + (pad * amount_to_pad).encode('utf-8')
	def __unpad(self, text):
		pad = text[-1] #ord(text[-1])
		return text[:-pad]
	def encrypt(self, raw):
		raw = self.__pad(raw)
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return cipher.encrypt(raw)
	def decrypt(self, enc):
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv )
		return self.__unpad(cipher.decrypt(enc))#.decode("utf-8"))

def getXmlValue(dom, root, xpath):
	ml = dom.getElementsByTagName(root)[0]
	node = ml.getElementsByTagName(xpath)[0]
	for n in node.childNodes:
		nodeValue = n.nodeValue
		return nodeValue
	return None


def gen_commandack_result(dnsId, cmdId, cmdType, resultCode):
	xml = u'''\
<?xml version="1.0" encoding="UTF-8"?>
<dnsCommandAck>
    <dnsId>%s</dnsId>
    <commandAck>
        <commandId>%s</commandId>
        <type>%d</type>
        <resultCode>%d</resultCode>
        <appealContent></appealContent>
        <msgInfo></msgInfo>
    </commandAck>
    <timeStamp>%s</timeStamp>
</dnsCommandAck>
''' % (dnsId, cmdId, cmdType, resultCode, time.strftime('%Y-%m-%d %H:%M:%S'))
    
	return xml


def dnsCommandAck(commandType, commandSequence, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, resultCode):
	global gPwd, gAESKey, gAESIV, ackhost, ackport

	sleep(1) 
	result = bytes(gen_commandack_result(dnsId, commandSequence, commandType, 0 if resultCode==0 else 2), encoding = 'utf-8')
	randVal = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
	lPwd = bytes(gPwd,'utf-8')

	if hashAlgorithm == 0: 
		_hashed_pwd = lPwd + randVal
		pwdHash = base64.b64encode(_hashed_pwd)
	elif hashAlgorithm == 1: 
		_hashed_pwd = hashlib.md5(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))
	elif hashAlgorithm == 2: 
		_hashed_pwd = hashlib.sha1(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))

	if compressionFormat == 0: _compressed_result = result
	elif compressionFormat == 1: _compressed_result = zlib.compress(result)

	e = AESCipher(gAESKey, gAESIV)
	if (gAESKey is not None) and (encryptAlgorithm == 1): 
		_encrypted_result = e.encrypt(_compressed_result)
	else: _encrypted_result = _compressed_result
    
	result = base64.b64encode(_encrypted_result)

	if hashAlgorithm == 0: 
		_hashed_result = _compressed_result + lPwd
		resultHash = base64.b64encode(_hashed_result)
	elif hashAlgorithm == 1: 
		_hashed_result = hashlib.md5(_compressed_result + lPwd).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))
	elif hashAlgorithm == 2: 
		_hashed_result = hashlib.sha1(_compressed_result + lPwd).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))

	commandVersion = 'v0.1'

	cl = osa.Client('http://%s:%d/DNSWebService/dnsCommandAck?wsdl' % (ackhost, ackport))
    
	try:
		r = cl.service.dns_commandack(dnsId, str(randVal, encoding='utf-8'), 
		str(pwdHash,encoding='utf-8'), str(result,encoding = 'utf-8'),
		str(resultHash,encoding='utf-8'), encryptAlgorithm, hashAlgorithm,compressionFormat, commandVersion)

		dom = xml.dom.minidom.parseString(r)
		if int(getXmlValue(dom, "return", "resultCode")) == 0:
			logger.info('return to drms dnsCommandAck success')
		else:
			logger.error('return to drms dnsCommandAck failed')

	except Exception as e:
		logger.error('dnsCommandAck exception:'+str(e))
		return -1


def genResult(rcode, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	lookaside = {
		0 : 'Done',
		1 : 'De-cryption error',
		2 : 'Certification error',
		3 : 'De-compression error',
		4 : 'Invalid type',
		5 : 'Malformed content',
		900 : 'Other error, try again'                                                        
	}
    
	xml = u'''<?xml version="1.0" encoding="UTF-8"?>
	<return>
		<resultCode>%d</resultCode>
		<msg>%s</msg>
	</return>''' % (rcode, lookaside[rcode])
    
	if commandId:    
		threading._start_new_thread(dnsCommandAck, (commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, rcode))

	return xml


def certificate(pwdHash, randVal, hashAlgorithm):                                             
	global gPwd
	if hashAlgorithm == 0: 
		raw = gPwd + randVal 
		return pwdHash == base64.b64encode(raw.encode('utf-8')).decode('utf-8')
	elif hashAlgorithm == 1: raw = hashlib.md5((gPwd + randVal).encode()).digest()
	elif hashAlgorithm == 2: raw = hashlib.sha1((gPwd + randVal).encode()).digest()
	else: return False
	return pwdHash == base64.b64encode(binascii.b2a_hex(raw)).decode()

def aesDecode(raw):
	aes = AESCipher(gAESKey, gAESIV)
	return aes.decrypt(raw)

def deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm):
	global gAESKey, gPwd
	raw = base64.b64decode(command.encode('utf-8'))
	if (gAESKey is not None) and (encryptAlgorithm == 1):
		data = aesDecode(raw)
	else: data = raw
	if hashAlgorithm == 0: hashed = data + gPwd.encode('utf-8')
	elif hashAlgorithm == 1: hashed = hashlib.md5((data + gPwd.encode('utf-8'))).digest()
	elif hashAlgorithm == 2: hashed = hashlib.sha1((data + gPwd.encode('utf-8'))).digest()
	else: return None
	if hashAlgorithm == 0:
		if base64.b64encode(hashed).decode('utf-8') != commandHash:
			return None
	else:
		if base64.b64encode(binascii.b2a_hex(hashed)).decode('utf-8') != commandHash:
			return None
	if compressionFormat == 0: cmd = data
	elif compressionFormat == 1: cmd = zlib.decompress(data)
	return cmd


class DRMSService(ServiceBase):
	@rpc(Unicode, Unicode, Unicode, Unicode, Unicode,Int, Long, Int, Int, 
		Int,Unicode, _out_variable_name = 'return', _returns = Unicode)

	def dns_command(ctx, dnsId, randVal, pwdHash, command, commandHash, commandType, 
	commandSequence, encryptAlgorithm, hashAlgorithm, compressionFormat, commandVersion):

		try:
			if not certificate(pwdHash, randVal, hashAlgorithm):
				logger.error('certificate error')
				return genResult(2, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm) 
			cmd = deCMDPre(command, compressionFormat, commandHash,hashAlgorithm, encryptAlgorithm)
			if not cmd:
				logger.error("webService Malformed content")
				return genResult(5, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)

			command_func = {18:respond18}
			if commandType in command_func:
				return command_func[commandType](cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
                #return respondBlack(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)

		except Exception as e: 
			logger.error('command error:'+str(e))
			return genResult(900, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
        



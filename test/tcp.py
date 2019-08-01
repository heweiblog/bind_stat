
import socket, threading, time

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(('192.168.5.41', 9999))

s.listen(100)

def tcplink(sock, addr):
	print('Accept new connection from %s:%s...' % addr)
	#sock.send(b'Welcome!')
	data = sock.recv(1024)
	print(data.decode('utf-8'))
	#print(str(data))
	#sock.send(('Hello, %s!' % data.decode('utf-8')).encode('utf-8'))
	sock.close()
	print('Connection from %s:%s closed.' % addr)


while True:
	sock, addr = s.accept()
	t = threading.Thread(target=tcplink, args=(sock, addr))
	t.start()



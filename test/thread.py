import time, threading

def loop():
	print('d')

t = threading.Thread(target=loop, name='LoopThread')

print(type(t))


def res(a,b):
	print(a,b)
	return a+b

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

ts = []
t1 = MyThread(res,(1,2))
ts.append(t1)
t2 = MyThread(res,(3,4))
ts.append(t2)
t1.start()
t2.start()
t1.join()
t2.join()

for t in ts:
	print(t.get_result())

print(t1.get_result(),t2.get_result())

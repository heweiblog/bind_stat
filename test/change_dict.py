

a= [{'type':'1','data':1},{'type':'2','data':2}]

for i in a:
	if i['type'] == '1':
		i['data'] = 3
print(a)

def change(d):
	d['data'] = 33

for k in a:
	change(k)

print(a)


import json

data = {
'a':1,
'b':'d',
'c':[1,2,3]
}

with open('json_test.json','w') as f:
	json.dump(data, f, sort_keys=True, indent=4, separators=(',', ': '))

with open('json_test.json','r') as f:
	d = json.load(f)
	print(d)
	print(type(d))


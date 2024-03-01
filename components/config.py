import json
import os

class merged_certain:
	path = None
	content = None
	raw = None
	exist = False
	def __init__(self, path):
		self.path = path
		self._read()

	def _read(self):
		try:
			with open(self.path, "rb") as f:
				self.content = json.loads(f.readline())
				self.raw = f.read()
			self.exist = True
		except FileNotFoundError:
			self.content = {}
			self.raw = b""

	def _GeneratePathToFile(self):
		splitpath = self.path.split("/")
		past = ""
		for directory in splitpath[:len(splitpath)-1]: #everything except the last element
			if not os.path.exists(past + directory):
				os.mkdir(past + directory)
			past += directory + "/"

	def save(self):
		if not self.exist:
			self._GeneratePathToFile()
		with open(self.path, "wb") as f:
			f.write(json.dumps(self.content).encode("utf-8")+b"\n")
			f.write(self.raw)
	#dict methods:
	def clear(self):
		self.content.clear()
	def items(self):
		return self.content.items()
	def keys(self):
		return self.content.keys()
	def values(self):
		return self.content.values()
	def __getitem__(self, item):
		return self.content[item]
	def __setitem__(self, item, value):
		self.content[item] = value
	def __delitem__(self, item):
		del self.content[item]
	def __contains__(self, item):
		return self.content.__contains__(item)

	#other
	def __str__(self):
		return str(self.content)

class merged_uncertain(merged_certain):
	path = None
	content = None
	raw = None
	exist = False
	def __init__(self, path, template):
		self.path = path
		self._read()
		if not self.exist:
			self.content = template
			self.save()

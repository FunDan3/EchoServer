import hashlib
def ReadFile(path, bytes = False):
	with open(path, "r" + ("b" if bytes else "")) as f:
		return f.read()
def hash(data, algorithm = None):
	if not algorithm:
		algorithm = "sha512"
	if type(data) == str:
		data = data.encode("utf-8")
	hash = hashlib.new(algorithm)
	hash.update(data)
	return hash

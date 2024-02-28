def ReadFile(path, bytes = False):
	with open(path, "r" + ("b" if bytes else "")) as f:
		return f.read()

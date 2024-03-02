import os
import pqcryptography as pqc

from . import common

allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_"

def _interface_init(interface):
	if interface.type == "post" and interface.json == None:
		interface.jsonize()

def verify(fields):
	def wrapper_maker(function):
		def wrapper(interface):
			_interface_init(interface)
			if not interface.verify(fields):
				interface.error(400, f"{function.__name__} has exactly this fields {fields}")
			else:
				function(interface)
		return wrapper
	return wrapper_maker

def login_validity(function):
	def wrapper(interface):
		_interface_init(interface)
		for login_character in interface.json["login"]:
			if login_character not in allowed_characters:
				interface.error(401, f"Login field can only contain letters numbers and underscore. Not {login_character}")
				break
		if not interface.finished:
			function(interface)
	return wrapper

def login_doesnt_exist(function):
	def wrapper(interface):
		_interface_init(interface)
		if os.path.exists(f"./storage/users/{interface.json['login']}"):
			interface.error(401, f"User {interface.json['login']} already exists!")
		else:
			function(interface)
	return wrapper

def login_does_exist(function):
	def wrapper(interface):
		_interface_init(interface)
		if os.path.exists(f"./storage/users/{interface.json['login']}"):
			function(interface)
		else:
			interface.error(401, f"User {interface.json['login']} doesnt exist!")
	return wrapper

def login_check(user_tokens):
	def init_wrapper(function):
		def wrapper(interface):
			_interface_init(interface)
			if user_tokens[interface.json["login"]] == common.hash(interface.json["token"]).hexdigest():
				function(interface)
			else:
				interface.error(403, "Tokens do not match.")
		return wrapper
	return init_wrapper

def username_validity(function):
	def wrapper(interface):
		_interface_init(interface)
		for login_character in interface.json["username"]:
			if login_character not in allowed_characters:
				interface.error(401, f"Username field can only contain letters numbers and underscore. Not {login_character}")
				break
		if not interface.finished:
			function(interface)
	return wrapper

def username_does_exist(function):
	def wrapper(interface):
		_interface_init(interface)
		if os.path.exists(f"./storage/users/{interface.json['username']}"):
			function(interface)
		else:
			interface.error(401, f"User {interface.json['username']} doesnt exist!")
	return wrapper



def algorithms_validity(function):
	def wrapper(interface):
		_interface_init(interface)
		if interface.json["kem_algorithm"] not in pqc.encryption.get_algorithms():
			interface.error(401, f"{interface.json['kem_algorithm']} is not supported by server. It only supports {pqc.encryption.get_algorithms()}")
			return
		if interface.json["sig_algorithm"] not in pqc.signing.get_algorithms():
			interface.error(401, f"{interface.json['sig_algorithm']} is not supported by server. It only supports {pqc.signing.get_algorithms()}")
			return
		key_size = pqc.encryption.get_details(interface.json["kem_algorithm"])["length_public_key"]
		sig_size = pqc.signing.get_details(interface.json["sig_algorithm"])["length_public_key"]
		if len(interface.data) != key_size+sig_size:
			interface.error(401, f"Key and sign for your algorithms are supposed to be exactly {key_size+sig_size} bytes long. Got: {len(interface.data)}")
			return
		function(interface)
	return wrapper

#! /usr/bin/python3
from httpdecolib import WebServer
import pqcryptography as pqc
import json
import os

from components import config
from components import common
from components import check

server_info = {"version": "0.0.1"}
settings = config.merged_uncertain("./storage/settings.json",
template = {"ip": "",
	"port": 23515,
	"ssl": {
		"enabled": False,
		"certificate_path": "",
		"key_path": "",
	}
})

user_tokens = {}

api = WebServer(settings["ip"], settings["port"])
if settings["ssl"]["enabled"]:
	api.convert_to_ssl(config["ssl"]["certificate_path"], config["ssl"]["key_path"])

@api.get("/read_public_keys")
@check.verify(["username"])
@check.username_validity
@check.username_does_exist
def read_public_keys(interface):
	with open(f"./storage/users/{interface.json['username']}/public_keys.mjson", "rb") as f:
		interface.write(f.read())
	interface.header("Content-Type", "text/json")
	interface.finish(200)

@api.post("/store_container")
@check.verify(["login", "token"])
@check.login_validity
@check.login_does_exist
@check.login(user_tokens)
def store_container(interface):
	encrypted_container = interface.data
	if len(encrypted_container) > 2**20*10: #10 megabytes
		interface.error(403, f"Container is two big. Maximal size is: {2**20*10}")
		return
	with open(f"./storage/users/{interface.json['login']}/container.epickle", "wb") as f:
		f.write(encrypted_container)
	interface.finish(200)

@api.post("/login")
@check.verify(["login", "token", "ReadContainer"])
@check.login_validity
@check.login_does_exist
@check.ensure_login_hashes(user_tokens)
@check.login(user_tokens)
def login(interface):
	if interface.json["ReadContainer"] == "yes":
		if not os.path.exists(f"./storage/users/{interface.json['login']}/container.epickle"):
			interface.error(404, "Container doesnt exists.")
			return
		with open(f"./storage/users/{interface.json['login']}/container.epickle", "rb") as f:
			interface.write(f.read())
	interface.finish(200)

@api.post("/register")
@check.verify(["login", "token", "kem_algorithm", "sig_algorithm"])
@check.login_validity
@check.login_doesnt_exist
@check.algorithms_validity
def register(interface):
	public_keys = config.merged_certain(f"./storage/users/{interface.json['login']}/public_keys.mjson")
	public_keys["kem_algorithm"] = interface.json["kem_algorithm"]
	public_keys["sig_algorithm"] = interface.json["sig_algorithm"]
	public_keys.raw = interface.data
	public_keys.save()

	user_token = common.hash(interface.json["login"]+interface.json["token"]).digest()
	user_tokens[interface.json["login"]] = user_token
	with open(f"./storage/users/{interface.json['login']}/token.hash", "wb") as f:
		f.write(user_token)
	interface.finish(200)

@api.get("/EchoMessagerServerInfo")
@check.verify([])
def EchoMessagerServerInfo(interface):
	interface.write(json.dumps(server_info)) #maybe I will add something later
	interface.header("Content-Type", "text/json")
	interface.finish(200)

@check.verify([])
@api.get("/ReadPrivacyPolicy")
def ReadPrivacyPolicy(interface):
	try:
		content = common.ReadFile(f"./storage/PrivacyPolicy.txt", bytes = True)
	except FileNotFoundError:
		content = f"create ./storage/PrivacyPolicy.txt to add privacy policy. Please try to write in in human language".encode("utf-8")
	interface.write(content)
	interface.header("Content-Type", "text/plain")
	interface.finish(200)

@check.verify([])
@api.get("/ReadTermsAndConditions")
def ReadTermsAndConditions(interface):
	try:
		content = common.ReadFile(f"./storage/TermsAndConditions.txt", bytes = True)
	except FileNotFoundError:
		content = f"create ./storage/TermsAndConditions.txt to add terms and conditions. Please try to write in in human language".encode("utf-8")
	interface.write(content)
	interface.header("Content-Type", "text/plain")
	interface.finish(200)

api.start()

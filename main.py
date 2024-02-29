#! /usr/bin/python3
from httpdecolib import WebServer
import pqcryptography as pqc
import json

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

user_tokens = config.merged_uncertain("./storage/users/tokens.json", template = {})

api = WebServer(settings["ip"], settings["port"])
if settings["ssl"]["enabled"]:
	api.convert_to_ssl(config["ssl"]["certificate_path"], config["ssl"]["key_path"])


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

	user_tokens[interface.json["login"]] = interface.json["token"]
	user_tokens.save()

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

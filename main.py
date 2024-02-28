#! /usr/bin/python3
from httpdecolib import WebServer
import pqcryptography as pqc
import json

from components import config
from components import common

server_info = {"version": "0.0.1"}
storage_directory = "./storage"
settings = config.merged_uncertain(f"{storage_directory}/settings.json",
template = {"ip": "",
	"port": 23515,
	"ssl": {
		"enabled": False,
		"certificate_path": "",
		"key_path": "",
	}
})


api = WebServer(settings["ip"], settings["port"])
if settings["ssl"]["enabled"]:
	api.convert_to_ssl(config["ssl"]["certificate_path"], config["ssl"]["key_path"])

@api.get("/EchoMessagerServerInfo")
def EchoMessagerServerInfo(interface):
	interface.write(json.dumps(server_info)) #maybe I will add something later
	interface.header("Content-Type", "text/json")
	interface.finish(200)

@api.get("/ReadPrivacyPolicy")
def ReadPrivacyPolicy(interface):
	try:
		content = common.ReadFile(f"{storage_directory}/PrivacyPolicy.txt", bytes = True)
	except FileNotFoundError:
		content = f"create {storage_directory}/PrivacyPolicy.txt to add privacy policy. Please try to write in in human language".encode("utf-8")
	interface.write(content)
	interface.header("Content-Type", "text/plain")
	interface.finish(200)

@api.get("/ReadTermsAndConditions")
def ReadTermsAndConditions(interface):
	try:
		content = common.ReadFile(f"{storage_directory}/TermsAndConditions.txt", bytes = True)
	except FileNotFoundError:
		content = f"create {storage_directory}/TermsAndConditions.txt to add terms and conditions. Please try to write in in human language".encode("utf-8")
	interface.write(content)
	interface.header("Content-Type", "text/plain")
	interface.finish(200)

api.start()

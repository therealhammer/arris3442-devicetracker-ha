
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
import hashlib
import json
import re
import requests
import sys
import binascii
import os
import logging
import voluptuous as vol

from homeassistant.components.device_tracker import (
	DOMAIN,
	PLATFORM_SCHEMA,
	DeviceScanner,
)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
	{
		vol.Required(CONF_HOST): cv.string,
		vol.Required(CONF_PASSWORD): cv.string,
		vol.Required(CONF_USERNAME): cv.string,
	}
)

def get_scanner(hass, config):
	_LOGGER.info("Calling get_scanner")
	scanner = Arris_3442_Scanner(config[DOMAIN])
	if scanner.success_init:
		return scanner

class Arris_3442_Scanner(DeviceScanner):
	def __init__(self, config):
		self.session = requests.Session()
		self.url = config[CONF_HOST]
		self.username = config[CONF_USERNAME]
		self.password = config[CONF_PASSWORD]
		self.last_results = {}
		self.success_init = False
		
		try:
			self.login(self.session, self.url , self.username, self.password)
			self.getDevices(self.session)
			self.success_init = True
		except requests.exceptions.RequestException:
			_LOGGER.debug("RequestException in %s", __class__.__name__)
			
	def login(self, session, url, username, password):
		#_LOGGER.warning("Trying logging into arris3442")
		r = session.get(f"{url}")
		# parse HTML
		soup = BeautifulSoup(r.text, "lxml")
		
		modem = get_firmware_handler(soup)

		(salt, iv) = modem.get_salt_and_iv()

		current_session_id = re.search(r".*var currentSessionId = '(.+)';.*", str(soup.head))[1]
		
		key = hashlib.pbkdf2_hmac('sha256', bytes(password.encode("ascii")), salt, iterations=1000, dklen=128/8)
		
		secret = {"Password": password, "Nonce": current_session_id}
		plaintext = bytes(json.dumps(secret).encode("ascii"))
		associated_data = "loginPassword"
		
		cipher = AES.new(key, AES.MODE_CCM, iv)
		cipher.update(bytes(associated_data.encode("ascii")))
		encrypt_data = cipher.encrypt(plaintext)
		encrypt_data += cipher.digest()
		
		login_data = modem.get_login_data(encrypt_data, username, salt, iv, associated_data)
		
		r = session.post(
			f"{url}/php/ajaxSet_Password.php",
			headers={
				"Content-Type": "application/json",
				"csrfNonce": "undefined"
			},
			data=json.dumps(login_data)
		)
		
		if not r.ok or json.loads(r.text)['p_status'] == "Fail":
			_LOGGER.warning("login failure", file=sys.stderr)
			exit(-1)
			
		result = json.loads(r.text)
		
		csrf_nonce = modem.get_csrf_nonce(result, key, iv)
		
		session.headers.update({
			"X-Requested-With": "XMLHttpRequest",
			"csrfNonce": csrf_nonce,
			"Origin": f"{url}/",
			"Referer": f"{url}/"
		})

		session.cookies.set(
			"credential",
			"eyAidW5pcXVlIjoiMjgwb2FQU0xpRiIsICJmYW1pbHkiOiI4NTIiLCAibW9kZWxuYW1lIjoiV"
			"EcyNDkyTEctODUiLCAibmFtZSI6InRlY2huaWNpYW4iLCAidGVjaCI6dHJ1ZSwgIm1vY2EiOj"
			"AsICJ3aWZpIjo1LCAiY29uVHlwZSI6IldBTiIsICJnd1dhbiI6ImYiLCAiRGVmUGFzc3dkQ2h"
			"hbmdlZCI6IllFUyIgfQ=="
		)

		r = session.post(f"{url}/php/ajaxSet_Session.php")
		
	def getDevices(self, session):
		#_LOGGER.warning("Trying to get devices")
		deviceWeb = session.get(f"{self.url}/php/status_lan_data.php?&lanData%5BdhcpDevInfo%5D=&lanData%5B")
		devices = json.loads(deviceWeb.text)['dhcpDevInfo']
		self.last_results = {}
		for i in devices:
			if (i[4] == "true"):
				_LOGGER.info("Device: " + i[0])
				_LOGGER.info("  MAC: " + i[1])
				_LOGGER.info("  IP: " + i[2])
				self.last_results.update( {i[1] :  i[0] })
		return devices
	
	def scan_devices(self):
		#_LOGGER.warning("Trying to scan_devices")
		del self.session
		self.session = requests.Session()
		self.login(self.session, self.url, self.username, self.password)
		self.getDevices(self.session)
		return self.last_results.keys()
		
	def get_device_name(self, device):
		#_LOGGER.warning("Trying to get_device_name")
		return self.last_results.get(device)

#Firmware

def get_firmware_handler(soup: BeautifulSoup):
	if bool(str(soup.head).count("01.01.117.01.EURO")):
		_LOGGER.info("Auto-detected firmware version 01.01.117.01.EURO")
		return FirmwareMid2018(soup)
	else:
		_LOGGER.info("Auto-detected firmware version 01.02.037.03.12.EURO.SIP")
		return FirmwareEarly2019(soup)

class Firmware():
	def __init__(self, soup: BeautifulSoup):
		self.soup = soup

	def get_salt_and_iv(self) -> tuple:
		pass

	def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str) -> dict:
		pass

	def get_csrf_nonce(self, login_response, key: bytes, iv: str):
		pass

class FirmwareEarly2019(Firmware):
	def get_salt_and_iv(self):
		their_salt = re.search(r".*var mySalt = '(.+)';.*", str(self.soup.head))[1]
		their_iv = re.search(r".*var myIv = '(.+)';.*", str(self.soup.head))[1]
		salt = bytes.fromhex(their_salt)
		iv = bytes.fromhex(their_iv)
		return (salt, iv)

	def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str):
		return {
			'EncryptData': binascii.hexlify(encrypt_data).decode("ascii"),
			'Name': username,
			'AuthData': associated_data
		}

	def get_csrf_nonce(self, login_response, key: bytes, iv: str):
		decCipher = AES.new(key, AES.MODE_CCM, iv)
		decCipher.update(bytes("nonce".encode()))
		decryptData = decCipher.decrypt(bytes.fromhex(login_response['encryptData']))
		return decryptData[:32].decode()

class FirmwareMid2018(Firmware):
	def get_salt_and_iv(self):
		salt = os.urandom(8)
		iv = os.urandom(8)
		return (salt, iv)

	def get_login_data(self, encrypt_data: bytes, username: str, salt: str, iv: str, associated_data: str):
		return {
			'EncryptData': binascii.hexlify(encrypt_data).decode("ascii"),
			'Name': username,
			'Salt': binascii.hexlify(salt).decode("ascii"),
			'Iv': binascii.hexlify(iv).decode("ascii"),
			'AuthData': associated_data
		}

	def get_csrf_nonce(self, login_response, key: bytes, iv: str):
		return login_response['nonce']

from firmware import get_firmware_handler

from bs4 import BeautifulSoup
from Crypto.Cipher import AES
import hashlib
import json
import re
import requests
import sys


from homeassistant.components.device_tracker import (
    DOMAIN,
    PLATFORM_SCHEMA,
    DeviceScanner,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    HTTP_HEADER_X_REQUESTED_WITH,
)
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

def get_scanner(hass, config):
	scanner = Arris_3442_Scanner(config)
	if scanner.success_init:
		return scanner
	
	
class Arris_3442_Scanner(DeviceScanner):
	def __init__(self, config[DOMAIN]):
		host = config[CONF_HOST]
		password = config[CONF_PASSWORD]
		username = config[CONF_USERNAME]
		
		session = requests.Session()
		
		self.success_init = False
		
		try:
			self.login(session, host, username, password)
			self.getDevices(session)
			self.success_init = False
		except requests.exceptions.ReaquestException:
			_LOGGER.debut("RequestException in %s", __class__.__name__)
			
	def login(session, url, username, password):
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
		
		r = session.put(
			f"{url}/php/ajaxSet_Password.php",
			headers={
				"Content-Type": "application/json",
				"csrfNonce": "undefined"
			},
			data=json.dumps(login_data)
		)
		
		if not r.ok or json.loads(r.text)['p_status'] == "Fail":
			print("login failure", file=sys.stderr)
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
		
	def getDevices(session):
		deviceWeb = session.get(f"{url}/php/status_lan_data.php?&lanData%5BdhcpDevInfo%5D=&lanData%5B")
		devices = json.loads(deviceWeb.text)['dhcpDevInfo']
		for i in devices:
			if (i[4] == "true"):
				print("Device: " + i[0])
				print("  MAC: " + i[1])
				print("  IP: " + i[2])
		return devices
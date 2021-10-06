from datetime import datetime
from dataclasses import dataclass
import requests

class UmbrellaClient:
	def __init__(self,integration_key,secret_key,organizationid,hostname="https://reports.api.umbrella.com/v2/organizations",limit=300):
		self.hostname = hostname
		self.integration_key = integration_key
		self.secret_key = secret_key
		self.organizationid = organizationid
		self.limit = limit

		self.valid_types = ["dns", "proxy", "firewall", "ip", "amp-retrospective"]

		self.token = self.authenticate()
		if not self.token:
			raise Exception(f"Could not obtain authentication token")

	def timestamp(self, timestamp=None):
		if timestamp:
			timestamp = timestamp + 1000
		else:
			timestamp = datetime.timestamp(datetime.fromisoformat(datetime.utcnow().strftime("%Y-%m-%dT00:00:00+00:00"))).__int__()
			timestamp = timestamp * 1000
		return (timestamp)

	def authenticate(self, url="https://management.api.umbrella.com/auth/v2/oauth2/token"):
		'''
		Grabs a Bearer token from the API. A dictionary is returned that can be used direcly as headers
		with the requests module

		Function will be used by init, and store the dictionary as self.token.

		TODO: implement logic to handle the validity time of the token

		https://developer.cisco.com/docs/cloud-security/#!reporting-v2-getting-started/create-api-access-token
		'''
		r = requests.post(url, timeout=30, auth=requests.auth.HTTPBasicAuth(self.integration_key, self.secret_key))
		if r.ok:
			token = r.json()["access_token"]
			auth_header = {
				"Authorization": f"Bearer {token}",
				"Content-Type": "application/json"
			}
			return (auth_header)
		else:
			return False
		
	def send_request(self,url):
		'''
		Main function for interacting with the API
		'''
		r = requests.get(f"{url}", timeout=30, allow_redirects=False, headers=self.token)
		if not r.ok:
			raise Exception(f"Could not connect to {url}. {r.json()}")
		'''
		The umbrella API tends to redirect (HTTP 302) the request. So we will check if the domain is the same. 

		We tell requests that we do not allow redirects so we can run logic against is_redirect and is_permanent_redirect 

		If you plan to use this in production, you may want to consider if this check is secure enough.
		'''
		if r.is_redirect or r.is_permanent_redirect:
			new_hostname = r.next.url.split("/")[2].split(".")[-2:]
			old_hostname = r.url.split("/")[2].split(".")[-2:]

			if new_hostname != old_hostname:
				raise Exception(f"Old and new hostname does not have matching domains: {old_hostname} / {new_hostname}")

			r = requests.get(f"{r.next.url}", timeout=30, allow_redirects=False, headers=self.token)

			if not r.ok:
				raise Exception(f"Error in connecting to re-directed url {r.url}. {r.json()}")

		return (r.json())

	def get_categories(self):
		'''
		Function to get the current categories from umbrella. 
		This can later be used as a parameter in the get_something functions
		'''
		r = self.send_request(f"{self.hostname}/{self.organizationid}/categories")
		
		data = UmbrellaCategories(r)
		
		return data

	def get_activity(self, timestamp=None, type=None, **kwargs):
		'''
		Function to retrive data "activity" data from the API

		https://developer.cisco.com/docs/cloud-security/#!reporting-v2-endpoints

		'''
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", 
		"ip", "ports", "identityids", "identitytypes", "applicationid", 
		"verdict", "ruleid", "filename", "securityoverridden", "bundleid",
		"threats", "threattypes", "ampdisposition", "antivirusthreats", 
		"x-traffic-type", "isolatedstate", "isolatedFileAction", 
		"datalosspreventionstate", "filternoisydomains", "httperrors"
		]
		
		parameters = []

		for key, value in kwargs.items():
			if key in valid_parameters:
				parameters.append(f"{key}={value}")

		if parameters:
			parameters.insert(0, "")

		if not type:
			url = f"{self.hostname}/{self.organizationid}/activity?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"
		elif type.lower() in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/activity/{type.lower()}?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"
		else:
			raise Exception(f"{type} not a valid activity type: Valid types: {','.join(self.valid_types)}")
		
		data = self.send_request(url)

		return data

	def get_top_identities(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", "ports", 
		"identityids", "identitytypes", "applicationid", "verdict", 
		"securityoverridden", "bundleid", "threats", "threattypes", 
		"ampdisposition", "antivirusthreats", "datalosspreventionstate", 
		"filternoisydomains"
		]

		parameters = []

		for key, value in kwargs.items():
			if key in valid_parameters:
				parameters.append(f"{key}={value}")
		
		if parameters:
			parameters.insert(0, "")

		if not type:
			url = f"{self.hostname}/{self.organizationid}/top-identities?from={timestamp}&to=now&limit={self.limit}&offset=0{'&'.join(parameters)}"
		elif type.lower() in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/top-identities/{type.lower()}?from={timestamp}&to=now&limit={self.limit}&offset=0{'&'.join(parameters)}"
		else:
			raise Exception(f"{type} not a valid identity type: Valid types: {','.join(self.valid_types)}")

		data = self.send_request(url)

		return data

	def get_top_destinations(self, timestamp=None, destination_type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", "ports", 
		"identityids", "identitytypes", "applicationid", "verdict", "sha256", 
		"securityoverridden", "bundleid", "threats", "threattypes", 
		"ampdisposition", "antivirusthreats", "datalosspreventionstate", 
		"filternoisydomains"
		]

		parameters = []

		for key, value in kwargs.items():
			if key in valid_parameters:
				parameters.append(f"{key}={value}")

		if parameters:
			parameters.insert(0, "")

		if not destination_type:
			raise Exception(f"Identity type is required for this function")
		elif destination_type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/top-destinations/{destination_type.lower()}?from={timestamp}&to=now&limit={self.limit}&offset=0{'&'.join(parameters)}"
		else:
			raise Exception(f"{destination_type} is not a valid destination type. Valid types: {','.join(self.valid_types)}")

		data = self.send_request(url)

		return data

	def get_top_categories(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policyCategories", "ip", 
		"identityIds", "identityTypes", "applicationId", "verdict", 
		"sha256", "securityOverridden", "bundleId", "threats", 
		"threatTypes", "ampDisposition", "antivirusThreats", 
		"dataLossPreventionState", "filterNoisyDomains"
		]

		parameters = []

		for key, value in kwargs.items():
			if key in valid_parameters:
				parameters.append(f"{key}={value}")

		if parameters: 
			parameters.insert(0, "")

		if not type:
			url = f"{self.hostname}/{self.organizationid}/top-categories?from={timestamp}&to=now&limit={self.limit}&offset=0{'&'.join(parameters)}"
		elif type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/top-categories/{type.lower()}?from={timestamp}&to=now&limit={self.limit}&offset=0{'&'.join(parameters)}"
		else:
			raise Exception(f"{type} not a valid type. Valid types: {','.join(self.valid_types)}")

		data = self.send_request(url)

		return data



	def get_security_activity(self, timestamp=None):
		'''
		Ready made function to grab acitivy-logs that has events in the "security" category. 
		'''
		timestamp = self.timestamp(timestamp)
		categories = self.get_categories()
		security_categories = []
		
		for i in categories.category_by_type["security"]:
			security_categories.append(str(i["id"]))
	
		data = self.get_activity(timestamp=timestamp, categories=','.join(security_categories))

		return data


@dataclass		
class UmbrellaCategories:
	type_list = list = []
	category_by_type = dict = {}
	category_by_id = dict = {}
	category_by_legacy_id = dict = {}
	def __init__(self,data):
		for i in data["data"]:
			if not i["type"] in self.type_list:
				self.type_list.append(i["type"])
			self.category_by_id[i["id"]] = i
			self.category_by_legacy_id[i["legacyid"]] = i
			if i["type"] not in self.category_by_type:
				self.category_by_type[i["type"]] = []
			else:
				self.category_by_type[i["type"]].append(i)
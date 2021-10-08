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

	def validate_parameters(self, valid_parameters_list=[], parameters_list=[]):
		'''
		Function used to validate the kwargs from the other functions. The valid list is stored within the function 
		itself, and this function expects a list of valid parameters and the kwargs to be passed.
		'''
		parameters = []

		for key, value in parameters_list.items():
			if key in valid_parameters_list:
				parameters.append(f"{key}={value}")

		if parameters:
			# We insert an empty parameter in the list so when "&".join() is used, an & is inserted at the begninning in the URL
			parameters.insert(0, "")
			
		return parameters

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
		"x-traffic-type", "isolatedstate", "isolatedfileaction", 
		"datalosspreventionstate", "filternoisydomains", "httperrors"
		]
		
		parameters = self.validate_parameters(valid_parameters, kwargs)

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

		parameters = self.validate_parameters(valid_parameters, kwargs)

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

		parameters = self.validate_parameters(valid_parameters, kwargs)

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
		"domains", "urls", "categories", "policycategories", "ip", "identityids", 
		"identitytypes", "applicationid", "verdict", "sha256", "securityoverridden", 
		"bundleid", "threats", "threattypes", "ampdisposition", "antivirusthreats", 
		"datalosspreventionstate", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if not type:
			url = f"{self.hostname}/{self.organizationid}/top-categories?from={timestamp}&to=now&limit={self.limit}&offset=0{'&'.join(parameters)}"
		elif type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/top-categories/{type.lower()}?from={timestamp}&to=now&limit={self.limit}&offset=0{'&'.join(parameters)}"
		else:
			raise Exception(f"{type} not a valid type. Valid types: {','.join(self.valid_types)}")

		data = self.send_request(url)

		return data

	def get_top_event_types(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"organizationid", "from", "to", "domains", "urls", "categories", 
		"policycategories", "ip", "identityids", "identitytypes", 
		"applicationid", "verdict", "securityoverridden", "bundleid", 
		"threats", "threattypes", "ampdisposition", "antivirusthreats", 
		"datalosspreventionstate", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/top-eventtypes?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_top_dns_query_types(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"order", "domains", "categories", "policycategories", "ip", 
		"identityids", "identitytypes", "applicationid", "verdict", 
		"threats", "threattypes", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/top-dns-query-types?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_organization_requests_by_hour(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", 
		"ports", "identityids", "identitytypes", "applicationid", 
		"verdict", "sha256", "securityoverridden", "bundleid", "threats", 
		"threattypes", "ampdisposition", "antivirusthreats", 
		"datalosspreventionstate", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/requests-by-hour/{type}?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"
		else:
			url = f"{self.hostname}/{self.organizationid}/requests-by-hour?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_organization_requests_by_hour_and_category(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", 
		"ports", "identityids", "identitytypes", "applicationid", 
		"verdict", "sha256", "securityoverridden", "bundleid", 
		"threats", "threattypes", "ampdisposition", 
		"antivirusthreats", "datalosspreventionstate", 
		"filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/categories-by-timerange/{type}?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"
		else:
			url = f"{self.hostname}/{self.organizationid}/categories-by-timerange?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_depolyment_status(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = ["threats", "threattypes"]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/deployment-status?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_bandwidth_by_hour(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", 
		"identityids", "identitytypes", "applicationid", "verdict", 
		"sha256", "securityoverridden", "bundleid", "ampdisposition", 
		"antivirusthreats", "datalosspreventionstate", "filternoisydomains",
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/bandwidth-by-hour?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_bandwidth_by_timerange(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", "identityids", 
		"identitytypes", "applicationid", "verdict", "sha256", 
		"securityoverridden", "bundleid", "ampdisposition", "antivirusthreats", 
		"timerange", "datalosspreventionstate", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/bandwidth-by-timerange?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_top_files(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", "identityids", 
		"identitytypes", "applicationid", "verdict", "sha256", 
		"securityoverridden", "bundleid", "ampdisposition", "antivirusthreats", 
		"datalosspreventionstate", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/top-files?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_total_requests(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", "ports", 
		"identityids", "identitytypes", "applicationid", "verdict", "ruleid", 
		"sha256", "securityoverridden", "bundleid", "threats", "threattypesp", 
		"ampdisposition", "antivirusthreats", "datalosspreventionstate", 
		"filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/total-requests?from={timestamp}&to=now{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_top_threats(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "categories", "policyCategories", "ip", "identityids", 
		"identitytypes", "applicationid", "verdict", "threats", 
		"threattypes", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/top-threats/{type}?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"
		else:
			url = f"{self.hostname}/{self.organizationid}/top-threats?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_top_threat_types(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "categories", "policyCategories", "ip", "identityids", 
		"identitytypes", "applicationid", "verdict", "threats", 
		"threattypes", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/top-threat-types/{type}?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"
		else:
			url = f"{self.hostname}/{self.organizationid}/top-threat-types?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_top_ips(self, timestamp=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "categories", "policycategories", "ip", "identityids", 
		"identitytypes", "applicationid", "verdict", "threats", 
		"threattypes", "filternoisynomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		url = f"{self.hostname}/{self.organizationid}/top-ips?from={timestamp}&to=now&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_summary(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", "ports",
		"identityids", "identitytypes", "applicationid", "verdict", "ruleid",
		"filename", "securityoverridden", "bundleid", "threats", "threattypes",
		"ampdisposition", "antivirusthreats", "datalosspreventionstate",
		"filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/summary/{type}?from={timestamp}&to=now&offset=0&limit={self.limit}{'&'.join(parameters)}"
		else:
			url = f"{self.hostname}/{self.organizationid}/summary?from={timestamp}&to=now&offset=0&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data


	def get_summaries_by_category(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", 
		"identityids", "identitytypes", "applicationid", "verdict", 
		"ruleid", "filename", "securityoverridden", "bundleid", "threats", 
		"threattypes", "ampdisposition", "antivirusthreats", 
		"datalosspreventionstate", "filternoisydomains"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/summaries-by-category/{type}?from={timestamp}&to=now&offset=0&limit={self.limit}{'&'.join(parameters)}"
		else:
			url = f"{self.hostname}/{self.organizationid}/summaries-by-category?from={timestamp}&to=now&offset=0&limit={self.limit}{'&'.join(parameters)}"

		data = self.send_request(url)

		return data

	def get_summaries_by_category(self, timestamp=None, type=None, **kwargs):
		timestamp = self.timestamp(timestamp)

		valid_parameters = [
		"domains", "urls", "categories", "policycategories", "ip", 
		"identityids", "identitytypes", "applicationid", "verdict", 
		"ruleid", "filename", "securityoverridden", "bundleid", "threats", 
		"threattypes", "ampdisposition", "antivirusthreats", 
		"datalosspreventionstate", "filternoisydomain"
		]

		parameters = self.validate_parameters(valid_parameters, kwargs)

		if type in self.valid_types:
			url = f"{self.hostname}/{self.organizationid}/summaries-by-destination/{type}?from={timestamp}&to=now&offset=0&limit={self.limit}{'&'.join(parameters)}"
		else:
			url = f"{self.hostname}/{self.organizationid}/summaries-by-destination?from={timestamp}&to=now&offset=0&limit={self.limit}{'&'.join(parameters)}"

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
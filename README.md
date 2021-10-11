# Umbrella Client

Python class to make it easier to interact with the Umbrella Reporting API (v2). This is not written by a programmer, so use it at your own risk!

The class/client is a work in progress. So be careful in pulling down new versions. I will try to not break old behaviour too much, but cant guarantee anything

# Obtaining API Credentials

You need to obtain API credentials from your umbrella dashboard in order for this client to work. 

The short version is:
<pre>
Umbrella Dashboard > Admin > API Keys > Umbrella Reporting > Generate Token
</pre>

A better description can be found here: https://developer.cisco.com/docs/cloud-security/#!reporting-v2-getting-started/create-api-access-token

# Usage
<pre>
from umbrella_client import UmbrellaClient

umbrella = UmbrellaClient(
	integration_key="some_key", 
	secret_key="more_sensitive_key", 
	organizationid="1234567"
)

print(umbrella.get_activity())
</pre>

# Default Behaviour
- api url defaults to: https://reports.api.umbrella.com/v2/organizarions
- limit default to 300
- from timestamp default to UTC midnight from the current day
- authentication url defaults to https://management.api.umbrella.com/v2/oauth2/token

# Currently implemented functions
Functions implemented in the class should mirror this documentation and naming as close as possible. Most arguments can be passed as they appear in the documentation. For example:
<pre>
umbrella.get_top_destinations(domains="google.com,bing.com")
</pre>
https://developer.cisco.com/docs/cloud-security/#!reporting-v2-endpoints

These functions are currently implemented. Refer to the API documentation to see what they do

- umbrella.get_activity() 
- umbrella.get_top_identities() 
- umbrella.get_top_destinations() 
- umbrella.get_top_categories()
- umbrella.get_top_dns_query_types() 
- umbrella.get_organization_requests_by_hour()
- umbrella.get_organization_requests_by_hour_and_category()
- umbrella.get_depolyment_status()
- umbrella.get_bandwidth_by_hour()
- umbrella.get_bandwidth_by_timerange()
- umbrella.get_top_files()
- umbrella.get_total_requests()
- umbrella.get_top_threats()
- umbrella.get_top_threat_types()
- umbrella.get_top_ips()
- umbrella.get_summary()
- umbrella.get_summaries_by_category()
- umbrella.get_summaries_by_destination()

Utility functions

***Still working on these***

- umbrella.get_categories() - Returns a dataclass with the categories structured in different ways

Other functions
- umbrella.get_security_activity() - Grabs events in the "security" category and displays them

I have not been able to test all that all of the functions return the correct data as the umbrella portal that I have access to does not use all the umbrella features and thus the data is missing

# Current limitations
- "to" timestamp is currently hard-coded to "now". So no support to change this without changing the class (for now)
- Offset is hard coded to 0. No support to retrive more eventes by manipulating the offset

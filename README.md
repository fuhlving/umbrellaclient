# Umbrella Client

Python class to make it easier to interact with the Umbrella Reporting API (v2). This is not written by a programmer, so use it at your own risk!

# Usage
<pre>
from umbrella_client import UmbrellaClient

umbrella = UmbrellaClient(integration_key="some_key", secret_key="more_sensitive_key", organizationid="1234567")

print(umbrella.get_activity())
</pre>

# Default Behaviour
- api url defaults to: https://reports.api.umbrella.com/v2/organizarions
- limit default to 300
- from timestamp default to UTC midnight from the current day
- authentication url defaults to https://management.api.umbrella.com/v2/oauth2/token

# Currently implemented functions
Functions implemented in the class should mirror this documentation and naming as close as possible
https://developer.cisco.com/docs/cloud-security/#!reporting-v2-endpoints

- umbrella.get_categories() - Returns a dataclass with the categories structured in different ways
- umbrella.get_activity() - Function to get various activities. All parameters except to, from, and offset and limit can be passed to the function
- umbrella.get_top_identities() - Function to get "Top" identities
- umbrella.get_top_destinations() - Function to get "Top" destinations
- umbrella.get_security_activity() - Function to get activity that has "security" as a category. If you want to query the categories defined in your installation. Use the get_categories functiond and look at "type_list" within the returned object. 


# Current limitations
- Authentication token is only created when the class is called. No logic implemented to check if the current token is valid and refresh it
- "to" timestamp is currently hard-coded to "now". So no support to change this without changing the class (for now)
- Offset is hard coded to 0. No support to retrive more eventes by manipulating the offset

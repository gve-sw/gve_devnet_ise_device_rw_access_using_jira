"""
Copyright (c) 2024 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

__author__ = "Trevor Maco <tmaco@cisco.com>, Mark Orszycki <morszyck@cisco.com>"
__copyright__ = "Copyright (c) 2024 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"

import json
import pathlib
from typing import ClassVar, Optional

import jinja2
import requests
import urllib3
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

from config.config import c
from logger.logrr import lm
from rule import json_rule

# Suppress only the single InsecureRequestWarning from urllib3 needed for unverified HTTPS requests.
urllib3.disable_warnings(InsecureRequestWarning)


class IseTacacs:
    """
    IseTacacs API Class, includes various methods for interacting with ISE ERS/Open API. Generate Singleton global instance.
    """

    _instance: ClassVar[Optional['IseTacacs']] = None

    # Class File Paths
    RULE_JSON_PATH: ClassVar[str] = str(pathlib.Path(__file__).parents[0] / 'rule.json')

    def __init__(self):
        """
        Initialize the ISE class (Basic Auth), load in the Authorization Rule JSON, and set up the requests session
        """
        self.session = None
        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self.auth = HTTPBasicAuth(c.ISE_USERNAME, c.ISE_PASSWORD)
        self._policy_id = None
        self._shell_profile = None
        self._matching_command_set = None
        self._active_auth_rules = None

        # Load in Raw Authorization Rule JSON, convert to template
        self._rule_template = jinja2.Template(json_rule)

        # Setup Session (handle 429 with custom backoff)
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount(c.OPEN_API_URL, HTTPAdapter(max_retries=retries))
        session.mount(c.ERS_URL, HTTPAdapter(max_retries=retries))
        self.session = session

    @classmethod
    def get_instance(cls):
        """
        Get Singleton instance of ISE Class
        :return: Singleton instance of ISE Class
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def policy_id(self):
        """
        Get the Policy ID
        :return: The Policy ID
        """
        return self._policy_id

    @policy_id.setter
    def policy_id(self, policy_id: str):
        """
        Set the Policy ID
        :param policy_id: The Policy ID
        """
        self._policy_id = policy_id

    @property
    def shell_profile(self):
        """
        Get the Shell Profile
        :return: The Shell Profile
        """
        return self._shell_profile

    @shell_profile.setter
    def shell_profile(self, shell_profile: str):
        """
        Set the Shell Profile
        :param shell_profile: The Shell Profile
        """
        self._shell_profile = shell_profile

    @property
    def matching_command_set(self):
        """
        Get the Matching Command Set
        :return: The Matching Command Set
        """
        return self._matching_command_set

    @matching_command_set.setter
    def matching_command_set(self, matching_command_set: list[str]):
        """
        Set the Matching Command Set
        :param matching_command_set: The Matching Command Set
        """
        self._matching_command_set = matching_command_set

    @property
    def active_auth_rules(self):
        """
        Get the Active Authorization Rules
        :return: The Active Authorization Rules
        """
        return self._active_auth_rules

    @active_auth_rules.setter
    def active_auth_rules(self, active_auth_rules: dict):
        """
        Set the Active Authorization Rules
        :param active_auth_rules: The Active Authorization Rules
        """
        self._active_auth_rules = active_auth_rules

    @property
    def rule_template(self):
        """
        Get the Rule Template
        :return: The Rule Template
        """
        return self._rule_template

    def get_wrapper(self, url: str, params: dict, headers: dict | None = None) -> dict | None:
        """
        REST Get API Wrapper, includes support for 429 rate limiting, and error handling
        :param url: Resource URL
        :param params: REST API Query Params
        :param headers: Optional Headers
        :return: Response Payload
        """
        try:
            # Get request using request session
            response = self.session.get(url=url, headers=headers if headers else self.headers, auth=self.auth,
                                        params=params,
                                        verify=False)
            if response.ok:
                return response.json()
            else:
                # Print failure message on error
                lm.lnp("Request FAILED: " + str(response.status_code) + f'\nResponse Content: {response.text}',
                       level="error")
                return None
        except requests.exceptions.RequestException as e:
            lm.lnp(f"Request failed with exception: {str(e)}", level="error")
            return None

    def post_wrapper(self, url: str, params: dict, body: dict) -> dict | None:
        """
        REST Post API Wrapper, includes support for 429 rate limiting and error handling
        :param url: Resource URL
        :param params: REST API Query Params
        :param body: REST API Body
        :return: Response Payload
        """
        try:
            response = self.session.post(url=url, headers=self.headers, auth=self.auth, params=params, json=body,
                                         verify=False)

            if response.ok:
                return response.json()
            else:
                # Print failure message on error
                lm.lnp("Request FAILED: " + str(response.status_code) + f'\nResponse Content: {response.text}',
                       level="error")
                return None
        except requests.exceptions.RequestException as e:
            lm.lnp(f"Request failed with exception: {str(e)}", level="error")
            return None

    def delete_wrapper(self, url: str, params: dict, body: dict) -> dict | None:
        """
        REST Delete API Wrapper, includes support for 429 rate limiting and error handling
        :param url: Resource URL
        :param params: REST API Query Params
        :param body: REST API Body
        :return: Response Payload
        """
        try:
            response = self.session.delete(url=url, headers=self.headers, auth=self.auth, params=params, json=body,
                                           verify=False)
            if response.ok:
                return response.json()
            else:
                # Print failure message on error
                lm.lnp("Request FAILED: " + str(response.status_code) + f'\nResponse Content: {response.text}',
                       level="error")
                return None
        except requests.exceptions.RequestException as e:
            lm.lnp(f"Request failed with exception: {str(e)}", level="error")
            return None

    def find_policy_set_id(self, policy_set_name: str) -> str | None:
        """
        Find a policy set ID by its name
        :param policy_set_name: The name of the policy set
        :return: The policy set ID, or None if not found
        """
        # Get All Policy Sets
        policy_sets_url = f"{c.OPEN_API_URL}/policy/device-admin/policy-set"
        params = {}

        response = self.get_wrapper(policy_sets_url, params)

        if response:
            policy_sets = response['response']
            # Iterate through policy sets, find the id for the specified policy set name
            for policy_set in policy_sets:
                if policy_set['name'] == policy_set_name:
                    # We found it!
                    lm.lnp(
                        f"Found the following Policy Set ID for Policy Set Name (`{policy_set_name}`): {policy_set['id']}",
                        level="info")
                    return policy_set['id']

        return None

    def find_shell_profile(self, shell_profile_name: str) -> dict | None:
        """
        Find a shell profile by its name
        :param shell_profile_name: The name of the shell profile
        :return: The shell profile, or None if not found
        """
        # Get All Shell Profiles
        policy_sets_url = f"{c.OPEN_API_URL}/policy/device-admin/shell-profiles"
        params = {}

        shell_profiles = self.get_wrapper(policy_sets_url, params)

        if shell_profiles:
            # Iterate through shell profiles, find the shell profile with the specified name
            for shell_profile in shell_profiles:
                if shell_profile['name'] == shell_profile_name:
                    # We found it!
                    lm.lnp(f"Found the following matching Shell Profile: {shell_profile}", level="info")
                    return shell_profile

        return None

    def find_command_set(self, command_set_names: list[str]) -> list[str]:
        """
        Compare provided list of command set names against available command set names, return a list valid command sets
        :param command_set_names: The names of the command sets
        :return: The matching command sets
        """
        # Track all provided command set names found (we should find them all ideally!)
        matching_command_set = []

        # Get All Command Sets
        policy_sets_url = f"{c.OPEN_API_URL}/policy/device-admin/command-sets"
        params = {}

        command_sets = self.get_wrapper(policy_sets_url, params)

        if command_sets:
            # Build quick list of current command sets names available
            current_command_set_names = [command_set['name'] for command_set in command_sets]

            # Iterate through provide command set name list, compare against available command sets
            for command_set_name in command_set_names:
                if command_set_name in current_command_set_names:
                    matching_command_set.append(command_set_name)

        lm.lnp(f"Found the following matching command sets: {matching_command_set}", level="info")
        return matching_command_set

    def get_authorization_rules(self):
        """
        Get all authorization rules with "rw_override" in the name (special designation for Jira RW Policy),
        used to initialize existing rules list
        :return: "rw_override" authorization rules
        """
        matched_rules = {}

        # Get list of current authorization rules
        authorization_rule_url = f"{c.OPEN_API_URL}/policy/device-admin/policy-set/{self._policy_id}/authorization"
        params = {}

        response = self.get_wrapper(authorization_rule_url, params)
        if response:
            authorization_rules = response['response']
            # Iterate through policy sets, find the id for the specified policy set name
            for auth_rule in authorization_rules:
                rule = auth_rule['rule']
                # Only Grab authorization rules with "rw_override" in the name
                if 'rw_override' in rule['name']:
                    matched_rules[rule['name']] = rule['id']

        return matched_rules

    def find_network_devices(self, device_filter: str) -> list[dict] | None:
        """
        Find network devices based on a filter (ip, hostname, etc.)
        :param device_filter: The filter to use
        :return: Matching network devices, or None if not found
        """
        # Get a network device based on the filter (if nothing is returned, device doesn't exist!)
        authorization_rule_url = f"{c.ERS_URL}/networkdevice"
        params = {"filter": device_filter}
        response = self.get_wrapper(authorization_rule_url, params)

        if response:
            if response['SearchResult']['total'] > 0:
                # Found devices!
                devices = response['SearchResult']['resources']
                lm.lnp(f"Found the following matching devices using filter `{device_filter}`: {devices}", level="info")
                return devices
            else:
                return None

    def create_authorization_rule(self, rule: dict) -> dict | None:
        """
        Create an authorization rule: utilize command set, shell profile, and dict representing matching conditional
        :param rule: Dict representing matching conditional
        :return: New Authorization Rule, or None if failed
        """
        # Create Authorization rule for specific LDAP user,
        authorization_rule_url = f"{c.OPEN_API_URL}/policy/device-admin/policy-set/{self._policy_id}/authorization"
        params = {}
        body = {"commands": self._matching_command_set, "profile": self._shell_profile, "rule": rule}

        authorization_rule = self.post_wrapper(authorization_rule_url, params, body)

        if authorization_rule:
            lm.lnp(f"Successfully created the following authorization rule: {authorization_rule}", level="info")

            # Add Authorization Rule Name to Active Rules dict
            self.active_auth_rules[authorization_rule['response']['rule']['name']] = \
                authorization_rule['response']['rule']['id']

        return authorization_rule

    def delete_authorization_rule(self, auth_rule_name: str) -> dict | None:
        """
        Remove an authorization rule by id (using name and the self.active_auth_rules dict mapping names to ids)
        :param auth_rule_name: The name of the authorization rule
        :return: Deletion response payload, or None if failed
        """
        # Delete Authorization rule by name if found
        if auth_rule_name in self.active_auth_rules:
            rule_id = self.active_auth_rules[auth_rule_name]
            authorization_rule_url = f"{c.OPEN_API_URL}/policy/device-admin/policy-set/{self._policy_id}/authorization/{rule_id}"
            params = {}
            body = {}

            response = self.delete_wrapper(authorization_rule_url, params, body)

            if response:
                lm.lnp(f"Successfully deleted the following authorization rule: {response}", level="info")

                # Delete Authorization Rule Name from Active Rules dict
                del self.active_auth_rules[auth_rule_name]

            return response
        else:
            # Special Raise to send it back to the front end
            raise Exception(
                f"Unable to find active authorization rule with name `{auth_rule_name}` in list of rules. Skipping...")


ise = IseTacacs.get_instance()  # Singleton instance of ISE

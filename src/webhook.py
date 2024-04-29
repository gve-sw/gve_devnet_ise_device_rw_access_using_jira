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

import ipaddress
import json
from datetime import datetime

import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from dateutil import parser

from config.config import c
from ise import ise
from logger.logrr import lm
from schemas import CreationWebhookData, BaseWebhookData

# Background Scheduler, schedule creation and destruction of Authorization rules
scheduler = BackgroundScheduler()
scheduler.start()


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if the provided IP address is a valid IP address
    :param ip_str: IP address string
    :return: True if valid, False if not
    """
    try:
        ipaddress.ip_address(ip_str)  # This will raise a ValueError if ip_str is not a valid IP address
        return True
    except ValueError:
        return False


def parse_datetime(datetime_str: str) -> datetime:
    """
    Parse the incoming datetime string and return a datetime object, check string is valid format during conversion
    :param datetime_str: Datetime string to parse
    :return: Datetime object
    """
    # Sanity check
    if datetime_str is None:
        raise ValueError("Start and/or End Schedule Feature Enabled, but not timestamp field(s) provided")

    try:
        # Try to parse the datetime string
        dt = parser.parse(datetime_str)
        # Convert naive datetime to aware using UTC, if not already aware
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            dt = pytz.utc.localize(dt)
        return dt
    except ValueError:
        raise ValueError(f"Invalid datetime format provided `{datetime_str}`")


def validate_webhook_data(data: CreationWebhookData | BaseWebhookData):
    """
    Validate the incoming webhook data, raise an exception if any validation fails (valid ips, valid date times for scheduling, etc.)
    :param data: Webhook data to validate
    """
    # Validate IP Address (both models have it) - check if ip valid, and ip is an actual network device in ISE
    ip_address = data.ip_address
    if not is_valid_ip(ip_address):
        raise ValueError(f"Invalid IP address received: {ip_address}")

    devices = ise.find_network_devices(f"ipaddress.EQ.{ip_address}")
    if not devices:
        raise ValueError(f"ISE Network Device not Found for the following IP: {ip_address}. Please check IP Address.")

    if isinstance(data, CreationWebhookData):
        # Check start_time is after current time if scheduling enabled
        if c.SCHEDULE_START:
            try:
                actual_start_dt = parse_datetime(data.actual_start)
                current_time = datetime.now(actual_start_dt.tzinfo)  # Use the timezone from the actual_start_dt
                if actual_start_dt < current_time:
                    raise ValueError(f"The start date `{data.actual_start}` must be in the future.")
            except ValueError as e:
                raise ValueError(f"Date Parsing Error : {str(e)}")

            # If end schedule feature is enabled, check end time is after start time
            if c.SCHEDULE_END:
                try:
                    actual_end_dt = parse_datetime(data.actual_end)
                    if actual_end_dt < actual_start_dt:
                        raise ValueError(f"The end datetime `{data.actual_end}` must be after the start datetime.")
                except ValueError as e:
                    raise ValueError(f"Date Parsing Error : {str(e)}")


def create_authorization_rule(data: CreationWebhookData) -> dict:
    """
    Create an ISE Authorization Rule based on the incoming webhook data, render raw JSON rule template with Webhook Values to create conditional
    :param data: Incoming Webhook Data
    :return: Response from ISE API Creation (Immediate or Scheduled)
    """
    # Build New Authorization Rule
    rule_template = ise.rule_template

    # Build data structure to inject into Jinja Rule template (field names must match those referenced in rule.json)
    username = data.assignee.split(' ')

    rule_data = {
        'first_name': username[0],
        'last_name': username[1],
        "ip_address": data.ip_address,
        "policy_name": f"{data.assignee}_rw_override-{data.ip_address}"
    }

    # Check if active rule already exists
    if rule_data['policy_name'] in ise.active_auth_rules:
        raise Exception(f"Active authorization rule for `{rule_data['policy_name']}` already exists! Skipping...")

    # Render the template with the provided data
    rendered_rule_str = rule_template.render(rule_data)
    rendered_rule = json.loads(rendered_rule_str)

    # Schedule authorization rule creation if enabled!
    if c.SCHEDULE_START:
        # Create/Convert incoming webhook datetime string to Datetime compatible object
        try:
            schedule_time = parse_datetime(data.actual_start)
        except ValueError as e:
            raise ValueError(f"Date Parsing Error : {str(e)}")

        response = scheduler.add_job(ise.create_authorization_rule, args=[rendered_rule], trigger='date',
                                     run_date=schedule_time)
        lm.lnp(f"Schedule authorization rule creation at: {schedule_time}")
    else:
        # Create new authorization policy immediately
        response = ise.create_authorization_rule(rendered_rule)

    if response and c.SCHEDULE_END:
        # Schedule Rule Removal if specified (either scheduling start job succeeded or rule creation succeeded)
        try:
            schedule_time = parse_datetime(data.actual_end)
        except ValueError as e:
            raise ValueError(f"Date Parsing Error : {str(e)}")

        response = scheduler.add_job(ise.delete_authorization_rule, args=[rule_data['policy_name']], trigger='date',
                                     run_date=schedule_time)
        lm.lnp(f"Schedule authorization rule deletion at: {schedule_time}")

    return response


def delete_authorization_rule(data: BaseWebhookData) -> dict | None:
    """
    Delete an ISE Authorization Rule based on the incoming webhook data, find the existing rule, get its id, perform deletion
    :param data: Incoming Webhook Data
    :return: Response from ISE API Deletion
    """
    # Reconstruct policy name (based on creation)
    policy_name = f"{data.assignee}_rw_override-{data.ip_address}"

    # Delete Authorization Rule
    return ise.delete_authorization_rule(policy_name)

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

from typing import Optional

from pydantic import BaseModel


# Pydantic schemas for the FastAPI App
class BaseWebhookData(BaseModel):
    assignee: str
    ip_address: str


# Extended model for creation webhook data (optional fields, depends on if scheduling feature enabled)
class CreationWebhookData(BaseWebhookData):
    actual_start: Optional[str] = None
    actual_end: Optional[str] = None

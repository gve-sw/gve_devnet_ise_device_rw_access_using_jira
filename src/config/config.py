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

import importlib
import pathlib
import secrets
from typing import ClassVar, Optional

from dotenv import dotenv_values


class Config:
    """
    Config class to handle all environment variables and settings for the FastAPI application
    """
    _instance: ClassVar[Optional['Config']] = None

    # PATHS - Adjust as necessary
    DIR_PATH: ClassVar[pathlib.Path] = pathlib.Path(__file__).parents[2]
    SRC_PATH: ClassVar[pathlib.Path] = pathlib.Path(__file__).parents[1]
    README_FILE_PATH: ClassVar[str] = str(pathlib.Path(__file__).parents[2] / 'README.md')
    ENV_FILE_PATH: ClassVar[str] = str(pathlib.Path(__file__).parents[2] / '.env')
    SETTINGS_FILE_PATH: ClassVar[str] = str(pathlib.Path(__file__).parents[0] / 'settings.py')

    # FastAPI Config
    APP_NAME: ClassVar[str] = 'ISE Device R/W Access with Jira'
    APP_VERSION: ClassVar[str] = '1.0.0'
    APP_SECRET_KEY: ClassVar[str] = secrets.token_hex(32)

    def __init__(self):
        # Load only the variables defined in the .env file
        self.env_vars = dotenv_values(self.ENV_FILE_PATH)
        for key, value in self.env_vars.items():
            setattr(self, key, value)

        # Load variables from user provided settings module
        self.settings_module = importlib.import_module("config.settings")
        self._load_settings_vars()

        # Set static variables based on environment variables
        ise_ip = getattr(self, 'ISE_IP', None)  # Use a default value or handle it appropriately
        self.BASE_URL = f"https://{ise_ip}"

    def _load_settings_vars(self):
        # Load all variables from the settings module
        for attribute_name in dir(self.settings_module):
            if not attribute_name.startswith('__') and not attribute_name.endswith('__'):
                attribute_value = getattr(self.settings_module, attribute_name)
                # Filter out functions and classes, only load non-callable attributes
                if not callable(attribute_value):
                    setattr(self, attribute_name, attribute_value)

                    # Add to Environment Variable Dict for printing
                    self.env_vars[attribute_name] = attribute_value

    @classmethod
    def get_instance(cls):
        """
        Singleton instance of the Config class
        :return: Config instance
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reload_config(cls):
        """
        Reload the Config instance
        :return: Config instance
        """
        cls._instance = None  # Reset the singleton instance
        return cls.get_instance()

    @property
    def ERS_URL(self):
        """
        ISE ERS API Base URL
        :return: ERS API Base URL
        """
        return f"{self.BASE_URL}/ers/config"

    @property
    def OPEN_API_URL(self):
        """
        ISE Open API Base URL
        :return: Open API Base URL
        """
        return f"{self.BASE_URL}/api/v1"


c = Config.get_instance()  # Singleton instance of Config

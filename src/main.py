#!/usr/bin/env python3
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

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from config.config import c
from ise import ise
from logger.logrr import lm
from routes import ise_router


def perform_sanity_checks():
    """
    Perform sanity checks on the minimum required parameters to create an ISE Authorization Rule and exit if any checks fail.
    As each check succeeds, assign the required parameters in the IseTacacs class
    """
    # Find Policy Set ID for Jira RW Policy (exit if not found)
    policy_id = ise.find_policy_set_id(c.POLICY_SET_NAME)
    if not policy_id:
        raise ValueError(
            f"Unable to find Policy Set ID for Policy Set: `{c.POLICY_SET_NAME}`. Please ensure Policy Set exists!")

    ise.policy_id = policy_id

    # Ensure Shell Profile exists (exit if not found)
    shell_profile = ise.find_shell_profile(c.SHELL_PROFILE_NAME)
    if not shell_profile:
        raise ValueError(f"Unable to find Shell Profile: `{c.SHELL_PROFILE_NAME}`. Please ensure Shell Profile exists!")

    ise.shell_profile = shell_profile['name']

    # Ensure All Command Set Names exists (returned list length should be the same as the provided list!)
    matching_command_set = ise.find_command_set(c.COMMAND_SET_NAMES)
    if len(matching_command_set) != len(c.COMMAND_SET_NAMES):
        raise ValueError(
            f"One or more command set names not found: {matching_command_set} vs {c.COMMAND_SET_NAMES}. Please ensure all command sets exist!")

    ise.matching_command_set = matching_command_set

    # Grab all existing authorization rules
    existing_rules = ise.get_authorization_rules()
    ise.active_auth_rules = existing_rules


def create_app() -> FastAPI:
    """
    Create FastAPI app with middleware and routers, define lifecycle events
    :return:
    """

    @asynccontextmanager
    async def app_lifespan(fastapi_app):
        """
        Context manager for FastAPI app lifespan events (define startup and shutdown events)
        :param fastapi_app: FastAPI app instance
        """
        lm.print_start_panel(app_name=c.APP_NAME)  # Print the start info message to console
        lm.print_config_table(config_instance=c)  # Print the config table

        # Before starting FastAPI server, perform sanity checks
        lm.p_panel(renderable="Sanity Check Provided Settings")
        try:
            perform_sanity_checks()
        except ValueError as e:  # Assuming perform_sanity_checks() raises ValueError on failure
            lm.lnp(str(e), "error")
            raise HTTPException(status_code=500, detail=f"Startup failed: {str(e)}")

        lm.p_panel(renderable="Listening for Webhooks...")

        yield

        lm.print_exit_panel()  # Print the exit info message to console

    fastapi_app = FastAPI(title=c.APP_NAME, version=c.APP_VERSION, lifespan=app_lifespan)  # Create the FastAPI app

    # Add CORS middleware for cross-origin requests
    fastapi_app.add_middleware(
        middleware_class=CORSMiddleware,
        allow_origins=["*"],  # For development, use ["*"]. For production, specify your frontend domain
        allow_credentials=True,  # Allows cookies
        allow_methods=["*"],  # Specifies the methods (GET, POST, etc.) allowed
        allow_headers=["*"],  # Allows all headers
    )

    # Add session middleware for session management
    fastapi_app.add_middleware(
        middleware_class=SessionMiddleware,
        secret_key=c.APP_SECRET_KEY  # Secret key for session management
    )

    fastapi_app.include_router(ise_router)  # Include the router
    return fastapi_app  # Return the FastAPI app


# Create the FastAPI app
app = create_app()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="critical")

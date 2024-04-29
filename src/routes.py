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

from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from logger.logrr import lm
from schemas import CreationWebhookData, BaseWebhookData
from webhook import create_authorization_rule, delete_authorization_rule, validate_webhook_data

ise_router = APIRouter()  # Create a router for the ISE app
templates = Jinja2Templates(directory="templates")  # Load the Jinja2 templates


# FastAPI Routes
@ise_router.get("/")
async def root():
    """
    Root route for the FastAPI server
    :return: JSONResponse, indicate server is online
    """
    try:
        # Return a simple JSON message
        return JSONResponse(content={"message": "FastAPI server is running"}, status_code=200)
    except Exception as e:
        lm.logger.error(f"Error in root function: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error in generating response")


@ise_router.post("/webhook/create")
async def create_webhook(data: CreationWebhookData = Body(...)):
    """
    This function handles the incoming webhook data and creates an ISE Authorization Rule
    """
    lm.lnp(f"Creation Webhook Data Received: {data}")

    # Validate Webhook Data, raise and return exception if there's a problem
    try:
        validate_webhook_data(data)
    except ValueError as e:
        # Return validation exception
        lm.lnp(f"{str(e)}", "error")
        raise HTTPException(status_code=400, detail=str(e))

    # Schedule (or Immediate) Authorization Rule Creation
    try:
        response = create_authorization_rule(data)
        if not response:
            raise HTTPException(status_code=500, detail="Failed to create authorization rule. See Logs.")
        return {"message": "Creation Webhook processed successfully"}
    except Exception as e:
        lm.lnp(f"Error processing Creation Webhook: {str(e)}", "error")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@ise_router.delete("/webhook/delete")
async def delete_webhook(data: BaseWebhookData = Body(...)):
    """
    This function handles the incoming webhook data and deletes an ISE Authorization Rule
    """
    lm.lnp(f"Deletion Webhook Data Received: {data}")

    # Perform immediate Authorization Rule Deletion
    try:
        response = delete_authorization_rule(data)
        if not response:
            raise HTTPException(status_code=500, detail="Failed to delete authorization rule. See Logs.")
        return {"message": "Deletion Webhook processed successfully"}
    except Exception as e:
        lm.lnp(f"Error processing Deletion Webhook: {str(e)}", "error")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

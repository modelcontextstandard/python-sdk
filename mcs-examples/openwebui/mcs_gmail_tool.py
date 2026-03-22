"""
title: MCS Gmail Agent
description: Gmail access via MCS with Auth0 Token Vault + LinkAuth. Authenticates users through a device-flow-like experience — no browser callback needed.
author: MCS
version: 1.0.0
requirements: mcs-driver-mail, mcs-adapter-gmail, mcs-auth, mcs-auth-auth0, mcs-auth-linkauth
"""

import json
import inspect
from pydantic import BaseModel, Field
from typing import Any

from mcs.auth.mixin import AuthMixin
from mcs.auth.auth0 import Auth0Provider
from mcs.auth.linkauth import LinkAuthAdapter
from mcs.driver.mail import MailDriver


class AuthMailDriver(AuthMixin, MailDriver):
    """MailDriver with transparent auth-challenge handling via AuthMixin."""


class Tools:
    class Valves(BaseModel):
        auth0_domain: str = Field(
            default="",
            description="Auth0 tenant domain (e.g. my-tenant.auth0.com)",
        )
        auth0_client_id: str = Field(
            default="",
            description="Auth0 application client ID",
        )
        auth0_client_secret: str = Field(
            default="",
            description="Auth0 application client secret",
        )
        auth0_audience: str = Field(
            default="",
            description="Auth0 API audience (e.g. https://mcs.local/api)",
        )
        linkauth_broker_url: str = Field(
            default="https://broker.linkauth.io",
            description="LinkAuth broker URL",
        )
        linkauth_api_key: str = Field(
            default="",
            description="LinkAuth broker API key",
        )

    def __init__(self):
        self.valves = self.Valves()
        self.driver = None
        self._build_driver()
        self._inject_tools()

    def _build_driver(self):
        """Build the driver with lazy auth (credential resolved on first tool call)."""
        if not self.valves.auth0_domain:
            # Driver can't be built without config — tools will be injected
            # when valves are updated and OpenWebUI re-instantiates
            return

        auth_adapter = LinkAuthAdapter(
            broker_url=self.valves.linkauth_broker_url,
            api_key=self.valves.linkauth_api_key or None,
            oauth_provider="auth0",
            oauth_scopes=["openid", "email", "offline_access"],
            oauth_extra_params={
                "audience": self.valves.auth0_audience,
                "connection": "google-oauth2",
            },
            display_name="Gmail Access via Auth0",
        )

        credential = Auth0Provider(
            domain=self.valves.auth0_domain,
            client_id=self.valves.auth0_client_id,
            client_secret=self.valves.auth0_client_secret,
            _auth=auth_adapter,
        )

        self.driver = AuthMailDriver(
            read_adapter="gmail",
            send_adapter="gmail",
            read_kwargs={"_credential": credential},
            send_kwargs={"_credential": credential},
        )

    def _inject_tools(self):
        """Discover MCS tools and inject them as OpenWebUI methods."""
        if not self.driver:
            return
        mcs_tools = self.driver.list_tools()

        for tool in mcs_tools:

            def make_caller(tool_name=tool.name):
                def dynamic_func(self, **kwargs) -> str:
                    if not self.driver:
                        return json.dumps({"error": "Auth0 not configured. Set domain, client_id, client_secret in Valves."})

                    # Handle OpenWebUI's kwargs wrapping
                    actual_params = {}
                    if "kwargs" in kwargs and isinstance(kwargs["kwargs"], str):
                        try:
                            actual_params = json.loads(kwargs["kwargs"])
                        except json.JSONDecodeError:
                            actual_params = kwargs
                    elif "kwargs" in kwargs and isinstance(kwargs["kwargs"], dict):
                        actual_params = kwargs["kwargs"]
                    else:
                        actual_params = kwargs

                    try:
                        result = self.driver.execute_tool(tool_name, actual_params)
                        if isinstance(result, (dict, list)):
                            return json.dumps(result, ensure_ascii=False)
                        return str(result)
                    except Exception as e:
                        return f"Error: {str(e)}"

                return dynamic_func

            func = make_caller()

            func.__name__ = tool.name
            func.__doc__ = (
                tool.description or tool.title or "No description provided."
            )

            # Build signature for OpenWebUI
            sig_params = [
                inspect.Parameter("self", inspect.Parameter.POSITIONAL_OR_KEYWORD)
            ]
            annotations = {}

            for param in tool.parameters:
                sig_params.append(
                    inspect.Parameter(
                        name=param.name,
                        kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        annotation=str,
                        default=inspect.Parameter.empty if param.required else None,
                    )
                )
                annotations[param.name] = str

            annotations["return"] = str
            func.__annotations__ = annotations
            func.__signature__ = inspect.Signature(sig_params)

            setattr(self, tool.name, func.__get__(self))

    def mcs_status(self) -> str:
        """Shows the status of the MCS Gmail Agent and available tools."""
        try:
            if not self.driver:
                return json.dumps({"status": "not configured", "message": "Set Auth0 credentials in Valves."})
            tools = self.driver.list_tools()
            tool_names = [t.name for t in tools]
            return json.dumps({
                "status": "active",
                "auth": "Auth0 Token Vault + LinkAuth",
                "broker": self.valves.linkauth_broker_url,
                "tools": tool_names,
            }, indent=2)
        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e),
            }, indent=2)

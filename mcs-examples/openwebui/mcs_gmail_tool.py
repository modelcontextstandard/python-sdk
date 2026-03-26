"""
title: MCS Gmail Agent
description: Gmail access via MCS. Reads, searches, and organises e-mail. Authenticates via Auth0 + LinkAuth device flow.
author: MCS
version: 2.0.0
requirements: mcs-driver-core>=0.2.2, mcs-driver-mail[gmail]>=0.1.2, mcs-driver-mailread>=0.1.2, mcs-driver-mailsend>=0.1.2, mcs-auth, mcs-auth-auth0, mcs-auth-linkauth
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
            default="dev-00uvh82o3xs8z0eb.us.auth0.com",
            description="Auth0 tenant domain",
        )
        auth0_client_id: str = Field(
            default="ZwMjRhIPVxo4GsVgQVLR8R6s83A9LXxP",
            description="Auth0 application client ID",
        )
        auth0_client_secret: str = Field(
            default="6D2lyFp0ErKXPGwchJpJtA7Ja0lliis2sgkMVNmVcTmzXRtb5hp2pbygryQsZlhB",
            description="Auth0 application client secret",
        )
        auth0_audience: str = Field(
            default="https://mcs.local/api",
            description="Auth0 API audience",
        )
        linkauth_broker_url: str = Field(
            default="http://127.0.0.1:8080",
            description="LinkAuth broker URL",
        )

    def __init__(self):
        self.valves = self.Valves()
        self.driver = None
        self._dynamically_generate_tools()

    def _ensure_driver(self):
        """Lazily build the real driver with auth on first tool call."""
        if self.driver:
            return

        auth_adapter = LinkAuthAdapter(
            broker_url=self.valves.linkauth_broker_url,
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

    def _dynamically_generate_tools(self):
        """Build the driver and inject its tools -- same pattern as the REST tool."""
        try:
            self._ensure_driver()
            if not self.driver:
                return
            mcs_tools = self.driver.list_tools()

            for tool in mcs_tools:

                def make_caller(tool_name=tool.name):
                    def dynamic_func(self, **kwargs) -> str:
                        self._ensure_driver()
                        if not self.driver:
                            return json.dumps({"error": "Driver not ready."})

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
                func.__signature__ = inspect.Signature(sig_params)  # type: ignore[attr-defined]

                setattr(self, tool.name, func.__get__(self))

        except Exception as e:
            print(f"MCS Gmail Init Error: {e}")

    def mcs_status(self) -> str:
        """Shows the status of the MCS Gmail Agent, installed package versions, and available tools."""
        import importlib.metadata as _meta
        diag = {}
        for pkg in ["mcs-driver-core", "mcs-driver-mail", "mcs-driver-mailread", "mcs-driver-mailsend"]:
            try:
                diag[pkg] = _meta.version(pkg)
            except _meta.PackageNotFoundError:
                diag[pkg] = "NOT INSTALLED"

        from mcs.driver.core.mcs_tool_driver_interface import Tool as _T
        diag["Tool_fields"] = [f.name for f in __import__("dataclasses").fields(_T)]

        try:
            if not self.driver:
                self._ensure_driver()
            if not self.driver:
                return json.dumps({"status": "not ready", "packages": diag}, indent=2)
            tools = self.driver.list_tools()
            return json.dumps({
                "status": "active",
                "packages": diag,
                "tools": [t.name for t in tools],
            }, indent=2)
        except Exception as e:
            return json.dumps({"status": "error", "packages": diag, "message": str(e)}, indent=2)

"""
title: MCS Gmail Agent
description: Gmail access via MCS. Reads, searches, and organises e-mail. Authenticates via Auth0 + LinkAuth device flow.
author: MCS
version: 2.0.0
requirements: mcs-driver-core>=0.2.2, mcs-driver-mail[gmail]>=0.1.2, mcs-driver-mailread>=0.2.1, mcs-driver-mailsend>=0.2.1, mcs-types-http>=0.1, mcs-types-cache>=0.1, mcs-adapter-http>=0.3, mcs-auth>=0.3.1, mcs-auth-auth0>=0.4.2, mcs-auth-oauth==0.3.0, mcs-auth-linkauth>=0.4.2
"""

import json
import inspect
from typing import Any

from mcs.auth.mixin import AuthMixin
from mcs.auth.auth0 import Auth0Provider
from mcs.auth.linkauth import LinkAuthConnector
from mcs.driver.mail import MailDriver


class AuthMailDriver(AuthMixin, MailDriver):
    """MailDriver with transparent auth-challenge handling via AuthMixin."""


class Tools:
    # ── CONFIGURE BEFORE USE ──────────────────────────────────
    # Set these values before pasting this tool into OpenWebUI.
    # Valves are NOT available at __init__ time, so the values
    # here must be valid for the tool to discover its functions.
    #
    # Auth0 credentials are needed TWICE:
    #   1. LinkAuth uses them for the initial OAuth login flow
    #      (configured server-side on the broker)
    #   2. Auth0Provider uses them locally for Token Vault
    #      exchange, MRRT, and Connected Accounts calls
    #
    AUTH0_DOMAIN = ""           # e.g. "my-tenant.us.auth0.com"
    AUTH0_CLIENT_ID = ""        # Auth0 application client ID
    AUTH0_CLIENT_SECRET = ""    # Auth0 application client secret
    AUTH0_AUDIENCE = ""         # e.g. "https://my-app/api"
    LINKAUTH_BROKER_URL = "https://broker.linkauth.io"
    LINKAUTH_API_KEY = ""       # API key for broker.linkauth.io

    def __init__(self):
        self.driver = None
        self._dynamically_generate_tools()

    def _ensure_driver(self):
        """Lazily build the real driver with auth on first tool call."""
        if self.driver:
            return

        # Connector: handles the OAuth login to obtain an Auth0 refresh token.
        # Auth0 credentials here are for the user-facing login flow.

        # Option A: LinkAuth (device-flow UX, works in Docker/CLI/sandboxes)
        # URLs are discovered automatically from the broker's OAuth provider config.
        auth_connector = LinkAuthConnector(
            broker_url=self.LINKAUTH_BROKER_URL,
            api_key=self.LINKAUTH_API_KEY or None,
            oauth_provider="auth0",
            oauth_scopes=["openid", "email", "offline_access"],
            oauth_extra_params={
                "audience": self.AUTH0_AUDIENCE,
                "connection": "google-oauth2",
            },
            display_name="Gmail Access via Auth0",
        )

        # Option B: Direct OAuth (opens browser, needs callback on localhost)
        # from mcs.auth.oauth import OAuthConnector
        # auth_connector = OAuthConnector(
        #     authorize_url=f"https://{self.AUTH0_DOMAIN}/authorize",
        #     token_url=f"https://{self.AUTH0_DOMAIN}/oauth/token",
        #     client_id=self.AUTH0_CLIENT_ID,
        #     client_secret=self.AUTH0_CLIENT_SECRET,
        #     scopes={"gmail": "openid email offline_access"},
        #     extra_params={
        #         "connection": "google-oauth2",
        #         "audience": self.AUTH0_AUDIENCE,
        #     },
        # )

        # Provider: uses the refresh token from the connector above for
        # server-to-server calls (Token Vault exchange, MRRT, Connected Accounts).
        # Same Auth0 credentials, different purpose.
        credential = Auth0Provider(
            domain=self.AUTH0_DOMAIN,
            client_id=self.AUTH0_CLIENT_ID,
            client_secret=self.AUTH0_CLIENT_SECRET,
            _auth=auth_connector,
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

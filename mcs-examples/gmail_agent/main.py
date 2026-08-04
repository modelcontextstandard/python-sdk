"""MCS Gmail Agent -- chat client for e-mail, with the full middleware chain.

This is the example where all three cross-cutting concerns run at once, and where
the interesting one is **auth**: pluggable credential providers behind a single
protocol.

- Auth0 Token Vault (RFC 8693) for federated token exchange
- LinkAuth broker for device-flow-like credential acquisition
- Direct OAuth 2.0 Authorization Code Flow
- Static tokens for quick testing

The client knows nothing about any of it. Three middleware run *inside* the driver
(``add_middleware``), so the driver keeps its full identity and the client just
talks to it:

- ``PermissionMiddleware`` gates every tool call behind a consent prompt. The
  client supplies only the handler.
- ``HooksMiddleware`` fires a pre-tool-use hook so the client can show progress
  ("a tool is running") WITHOUT inspecting the LLM output. That is the point: the
  client hands the raw message to ``process_llm_response`` as a black box and
  learns of tool activity only through this callback.
- ``AuthMiddleware`` catches a credential challenge at the execution boundary and
  turns it into an in-band result, so the LLM can present the login URL as part of
  its answer instead of the program crashing.

Chain order is list order, outermost first:
``Permission -> Hooks -> Auth -> the real tool``. Permission sits *outside* Hooks
deliberately -- a denied call never runs, so it should never announce itself as
running either.

Everything else -- the loop, the display, the streaming/blocking choice -- is the
shared scaffolding every example uses. Only the driver setup below is Gmail's.

Usage:
    # Auth0 with pre-existing refresh token (from .env):
    python main.py --auth0-token

    # Auth0 via browser login (Authorization Code Flow):
    python main.py --auth0-oauth

    # Auth0 via LinkAuth broker (device-flow UX):
    python main.py --auth0-linkauth

    # LinkAuth broker direct (no Auth0):
    python main.py --linkauth

    # Quick test with a static Google OAuth2 access token:
    python main.py --gmail-token ya29.xxx

    # Any of the above, non-streaming or with debug output:
    python main.py --auth0-token --no-stream --debug

Requires:
    pip install mcs-driver-mail[gmail] mcs-auth-auth0 mcs-permission mcs-hooks         litellm rich python-dotenv
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _shared import ChatSession, ChatView, base_parser  # noqa: E402

from mcs.auth.middleware import AuthMiddleware  # noqa: E402
from mcs.permission.middleware import PermissionMiddleware  # noqa: E402
from mcs.hooks.middleware import HooksMiddleware  # noqa: E402
from mcs.driver.mail import MailDriver  # noqa: E402
from mcs.driver.mail.tooldriver import MailToolDriver  # noqa: E402


def _build_credential(args: argparse.Namespace):
    """Build the appropriate CredentialProvider based on CLI args."""
    if args.gmail_token:
        return None  # Static token handled separately

    if args.auth0_token:
        from mcs.auth.auth0 import Auth0Provider

        for var in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_REFRESH_TOKEN"):
            if not os.environ.get(var):
                raise SystemExit(f"Missing environment variable: {var}")

        return Auth0Provider(
            domain=os.environ["AUTH0_DOMAIN"],
            client_id=os.environ["AUTH0_CLIENT_ID"],
            client_secret=os.environ["AUTH0_CLIENT_SECRET"],
            refresh_token=os.environ["AUTH0_REFRESH_TOKEN"],
            connection_scopes={"gmail": [
                "https://mail.google.com/",
                "openid", "email", "profile",
            ]},
        )

    if getattr(args, "auth0_oauth", False):
        from mcs.auth.auth0 import Auth0Provider
        from mcs.auth.oauth import OAuthConnector

        for var in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"):
            if not os.environ.get(var):
                raise SystemExit(f"Missing environment variable: {var}")

        domain = os.environ["AUTH0_DOMAIN"]
        audience = os.environ.get("AUTH0_AUDIENCE", f"https://{domain}/api/v2/")

        auth_adapter = OAuthConnector(
            authorize_url=f"https://{domain}/authorize",
            token_url=f"https://{domain}/oauth/token",
            client_id=os.environ["AUTH0_CLIENT_ID"],
            client_secret=os.environ["AUTH0_CLIENT_SECRET"],
            scopes={"gmail": "openid email offline_access"},
            extra_params={
                "connection": "google-oauth2",
                "audience": audience,
                "connection_scope": "https://mail.google.com/",
                "prompt": "consent",
            },
        )
        return Auth0Provider(
            domain=domain,
            client_id=os.environ["AUTH0_CLIENT_ID"],
            client_secret=os.environ["AUTH0_CLIENT_SECRET"],
            connection_scopes={"gmail": [
                "https://mail.google.com/",
                "openid", "email", "profile",
            ]},
            _auth=auth_adapter,
        )

    if getattr(args, "auth0_linkauth", False):
        from mcs.auth.auth0 import Auth0Provider
        from mcs.auth.linkauth import LinkAuthConnector

        for var in ("AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"):
            if not os.environ.get(var):
                raise SystemExit(f"Missing environment variable: {var}")

        broker_url = os.environ.get("LINKAUTH_BROKER_URL", "http://localhost:8080")
        audience = os.environ.get("AUTH0_AUDIENCE", "")
        auth_adapter = LinkAuthConnector(
            broker_url=broker_url,
            api_key=os.environ.get("LINKAUTH_API_KEY"),
            oauth_provider="auth0",
            oauth_scopes=["openid", "email", "offline_access"],
            oauth_extra_params={"audience": audience, "connection": "google-oauth2"},
            display_name="Auth0 Login (Gmail)",
        )
        return Auth0Provider(
            domain=os.environ["AUTH0_DOMAIN"],
            client_id=os.environ["AUTH0_CLIENT_ID"],
            client_secret=os.environ["AUTH0_CLIENT_SECRET"],
            connection_scopes={"gmail": [
                "https://mail.google.com/",
                "openid", "email", "profile",
            ]},
            _auth=auth_adapter,
        )

    if args.linkauth:
        from mcs.auth.linkauth import LinkAuthProvider

        broker_url = os.environ.get("LINKAUTH_BROKER_URL", "http://localhost:8000")
        return LinkAuthProvider(
            broker_url=broker_url,
            api_key=os.environ.get("LINKAUTH_API_KEY"),
            template="google_mail",
            display_name="Gmail Access",
        )

    raise SystemExit("No authentication method specified.")


def _build_driver(args: argparse.Namespace, view: ChatView) -> MailDriver:
    """A Gmail MailDriver with the three concerns attached."""
    gmail_kwargs: dict = {}
    if args.sender_name:
        gmail_kwargs["sender_name"] = args.sender_name

    credential = _build_credential(args)
    if credential is not None:
        gmail_kwargs["_credential"] = credential
    else:
        gmail_kwargs["access_token"] = args.gmail_token

    tool_driver = MailToolDriver(
        read_adapter="gmail",
        send_adapter="gmail",
        read_kwargs=gmail_kwargs,
        send_kwargs=gmail_kwargs,
    )
    driver = MailDriver(_tooldriver=tool_driver)

    # Order is list order, outermost first. Permission first: it decides whether the
    # call happens at all, so nothing inside it should run -- or announce itself --
    # before the user has agreed. Auth sits innermost, closest to execution, where a
    # credential challenge is actually raised.
    driver.add_middleware(PermissionMiddleware(consent_handler=view.ask_consent))
    driver.add_middleware(HooksMiddleware(pre=[view.tool_running]))
    driver.add_middleware(AuthMiddleware())
    return driver


def main() -> None:
    load_dotenv()
    p = base_parser("MCS Gmail agent -- e-mail over the full middleware chain",
                    default_model="gpt-5.4")
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("--gmail-token", help="Static Google OAuth2 access token (quick test)")
    auth.add_argument("--auth0-token", action="store_true",
                      help="Auth0 with pre-existing refresh token (needs AUTH0_REFRESH_TOKEN in .env)")
    auth.add_argument("--auth0-oauth", action="store_true",
                      help="Auth0 via browser login (Authorization Code Flow)")
    auth.add_argument("--auth0-linkauth", action="store_true",
                      help="Auth0 via LinkAuth broker (device-flow UX)")
    auth.add_argument("--linkauth", action="store_true", help="LinkAuth broker direct (no Auth0)")
    p.add_argument("--sender-name", default=None, help="Display name for outgoing e-mails")
    args = p.parse_args()

    view = ChatView(debug=args.debug)
    driver = _build_driver(args, view)
    view.tools_discovered([t.name for t in driver.list_tools()])

    ChatSession(
        driver, args.model, view=view,
        streaming=args.stream, native_tools=args.native_tools,
        api_base=args.api_base, api_key=args.api_key,
        title="MCS Gmail Agent",
        banner_extra=["Concerns: permission -> hooks -> auth"],
    ).run()


if __name__ == "__main__":
    main()

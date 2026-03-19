"""OAuth 2.0 Authorization Code adapter and provider for MCS."""

from .oauth_adapter import OAuthAdapter
from .oauth_provider import OAuthProvider

__all__ = ["OAuthAdapter", "OAuthProvider"]

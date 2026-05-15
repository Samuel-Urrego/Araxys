"""CORS Policy Manager — origin allowlisting, preflight handling, header injection."""

from araxys.cors.config import CORSConfig
from araxys.cors.middleware import CORSMiddleware

__all__ = [
    "CORSConfig",
    "CORSMiddleware",
]

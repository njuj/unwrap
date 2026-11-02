"""unwrap — peel obfuscation off malicious scripts statically, without ever running them."""

__version__ = "0.1.0"

from .engine import Layer, Result, unwrap  # noqa: E402

__all__ = ["Layer", "Result", "unwrap", "__version__"]

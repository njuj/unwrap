"""unwrap — peel obfuscation off malicious scripts statically, without ever running them."""

__version__ = "0.2.0"

from .containers import Container, open_container  # noqa: E402
from .engine import Layer, Result, unwrap  # noqa: E402

__all__ = ["Container", "Layer", "Result", "open_container", "unwrap", "__version__"]

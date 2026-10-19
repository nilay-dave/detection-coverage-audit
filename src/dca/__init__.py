"""detection-coverage-audit: measure which ATT&CK techniques are blind in production."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("detection-coverage-audit")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"

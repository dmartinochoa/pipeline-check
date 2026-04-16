from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("pipeline_check")
except PackageNotFoundError:
    __version__ = "0.1.0"

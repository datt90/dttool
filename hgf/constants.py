from typing import Any, Literal, Optional

DEFAULT_CONFIG = "config.json"
RETRY_TIMEOUT = 30  # sec
DEFAULT_DB_PROD_URL = "sqlite:///hgfv3.sqlite"

Config = dict[str, Any]
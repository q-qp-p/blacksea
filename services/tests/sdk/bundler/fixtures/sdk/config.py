from .errors import ConfigError
from ._util import normalize


class Config:
    def __init__(self, token):
        if not token:
            raise ConfigError("token required")
        self.token = normalize(token)

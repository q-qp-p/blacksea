from . import codec              # sibling submodule
from ..config import Config      # `from ..config import X`  (up one package)
from ..errors import ApiError


class Transport:
    def __init__(self, config):
        if not isinstance(config, Config):
            raise ApiError("Transport requires a Config instance")
        self.config = config

    def send(self, message):
        return codec.encode(message + " #" + self.config.token)

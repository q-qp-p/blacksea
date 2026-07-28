from . import _util               # `from . import y`  (relative, no submodule part)
from .config import Config
from .errors import ApiError
from .sub.transport import Transport


class Client:
    def __init__(self, config):
        if not isinstance(config, Config):
            raise ApiError("Client requires a Config instance")
        self.config = config
        self.transport = Transport(config)

    def greet(self, who):
        name = _util.normalize(who)
        return self.transport.send("hello " + name)

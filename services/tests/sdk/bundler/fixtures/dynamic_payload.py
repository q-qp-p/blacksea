"""Loads a plugin by runtime string -- invisible to static analysis.

Build this with `--include-module sdk.plugins.extra` to vendor the plugin.
"""

import importlib

name = "extra"
plugin = importlib.import_module("sdk.plugins." + name)


if __name__ == "__main__":
    print(plugin.run())

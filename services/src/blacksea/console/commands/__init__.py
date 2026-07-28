"""blacksea.console.commands — the noun-verb command modules.

Each module exposes click commands/groups that `cli.py` registers on the root group. These modules
(and only these, plus `cli.py`/`render.py`) import click/rich; the facade stays pure.
"""

"""blacksea.correlation — the read/correlation layer over the record store.

**Today (MVP):** a shared, read-only *view* library over the brain-written
``records`` table. It exists so operator-facing consumers — the read-only web
observer and the future terminal console — render sessions, hit-rate, caution
distribution, and raw event feeds from *one* set of query builders and row
mappers instead of each re-implementing the SQL. It never writes to any table.

**Future:** this module is where the stateful correlation/attribution engine
(session state machine + actor graph; full design spec in ``context.md``) will
live. The read views here are deliberately shaped toward that: ``session_views``
already groups by ``(instance_token, session_id)`` and keys on the §6.3
``session_record_id`` form, so the engine can later supersede the approximation
with a stateful, attribution-grade version behind the same names.

Public surface: the value types (``RecordFilter`` and the view dataclasses) plus
the ``reader`` functions. Every reader has a sync ``foo`` and an async ``afoo``
variant sharing one SQL builder + mapper.
"""

from __future__ import annotations

from . import queries, reader
from .models import (
    CautionCount,
    RecordCursor,
    RecordDetail,
    RecordFilter,
    RecordSummary,
    SessionView,
    TimeBucket,
)
from .reader import (
    acaution_distribution,
    acount_records,
    aget_record,
    ahit_rate,
    alist_records,
    arecords_after,
    asession_views,
    caution_distribution,
    count_records,
    get_record,
    hit_rate,
    list_records,
    records_after,
    session_views,
)

__all__ = [
    "queries",
    "reader",
    # value types
    "RecordFilter",
    "RecordCursor",
    "RecordSummary",
    "RecordDetail",
    "SessionView",
    "TimeBucket",
    "CautionCount",
    # sync readers
    "list_records",
    "get_record",
    "count_records",
    "records_after",
    "hit_rate",
    "caution_distribution",
    "session_views",
    # async readers
    "alist_records",
    "aget_record",
    "acount_records",
    "arecords_after",
    "ahit_rate",
    "acaution_distribution",
    "asession_views",
]

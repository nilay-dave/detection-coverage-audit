# Detect a log source silently dropping a field
labels: enhancement

Field presence per source is already computed on every run and then thrown away.
Storing it would let the tool answer a question it is one small step from
answering: which field did we stop collecting, and which live detections depended
on it.

This is the same failure as the audit's current findings, arriving over time
rather than being there from the start, and it is arguably the more dangerous
version because nobody is looking.

## What to do

- Write each run's per source, per field presence to a small history file keyed by run timestamp.
- Add `dca drift --history <file>` that reports fields whose presence dropped by more than a configurable fraction between runs, and names the rules that reference them.
- Treat a field that disappeared entirely as a separate, louder finding than one that merely fell.

## Design note

The threshold needs care. Presence legitimately varies between windows, and a
drift detector that fires on normal variation gets switched off. Start by
reporting the magnitude of every change and let the operator pick a threshold,
rather than picking one for them.

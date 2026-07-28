#!/usr/bin/env bash
# NOP staging vessel — stages the bundled payload as-is.
# Usage: ./setup.sh <context.json>
#
# A real staging vessel would wrap the payload in a delivery container
# (bash heredoc, Jupyter notebook, macro, fake binary, etc.). This one
# just copies it so the build pipeline can be exercised end-to-end.
set -euo pipefail

CONTEXT_JSON="${1:?usage: setup.sh <context.json>}"

# Parse context.json (Python one-liner to avoid jq dependency).
BUNDLED=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['bundled_payload_path'])")
OUTPUT=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['output_dir'])")
OUTPUT_ROOT=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['output_dir_root'])")

mkdir -p "$OUTPUT"
cp "$BUNDLED" "$OUTPUT/bait.py"
chmod +x "$OUTPUT/bait.py"

# Declare the output (§17.11 contract) — artifact.json goes in the root, not in to_stage/
cat > "$OUTPUT_ROOT/artifact.json" <<'EOF'
{
  "primary": "bait.py",
  "files": {
    "bait.py": {"role": "script"}
  }
}
EOF

# Operator-facing staging/trigger note (docs/bait-authoring.md §5) — goes in the root next to
# artifact.json, never in to_stage/ (this file must never reach the target).
cat > "$OUTPUT_ROOT/how_to_stage.md" <<'EOF'
# How to stage this bait

## What this is
The NOP vessel: `bait.py` is the bundled SDK payload staged unchanged, with no delivery
wrapper or cover story. It only exists to exercise the build pipeline end-to-end.

## How to stage it
Copy `bait.py` to a writable path on the target and make it executable
(`chmod +x bait.py`), or leave it as a plain script run via an interpreter.

## Exact trigger command
```
python3 bait.py
```
EOF

echo "staged: $OUTPUT/bait.py"

"""Remove evaluator host/account metadata before publishing agent captures."""
from __future__ import annotations

import json
import re

_REMOVED = {'sessionid', 'uuid', 'messagingsocketpath', 'credentialexpiresat', 'memorypaths', 'accountuuid', 'accountid', 'organizationuuid', 'organizationid', 'oauthaccount'}


# Per-user host paths that identify the evaluator's machine or account.
# macOS hands out per-user temp roots as /var/folders/<a>/<b>/T and
# tempfile.gettempdir() may return either that or the /private/var form.
_HOST_PATHS = (
    (re.compile(r'(?:/private)?/var/folders/[^/\s"\\]+/[^/\s"\\]+/T(?=/|\b|$)'), '/tmp/evaluator'),  # nosec B108 -- replacement text, never a file path
    (re.compile(r'(?i)\b([A-Z]):(\\\\|\\|/)Users\2(?!evaluator\b)[^\\/\s"]+'), r'\1:\2Users\2evaluator'),
    (re.compile(r'/Users/(?!evaluator\b)[^/\s"\\]+'), '/home/evaluator'),
    (re.compile(r'/home/(?!evaluator\b)[^/\s"\\]+'), '/home/evaluator'),
)


def scrub_host_paths(text: str) -> str:
    """Replace evaluator-identifying host paths, leaving everything else
    byte-for-byte unchanged (safe on raw JSONL as well as decoded strings)."""
    for pattern, replacement in _HOST_PATHS:
        text = pattern.sub(replacement, text)
    return text


def scrub_evidence(value):
    if isinstance(value, dict):
        return {key: scrub_evidence(item) for key, item in value.items()
                if re.sub(r'[^a-z]', '', key.lower()) not in _REMOVED and 'plugin' not in key.lower()}
    if isinstance(value, list):
        return [scrub_evidence(item) for item in value]
    if isinstance(value, str):
        value = scrub_host_paths(value)
        lines = [line for line in value.split('\n') if line.strip()]
        if len(lines) > 1 and all(line.lstrip().startswith('{') for line in lines):
            try:
                return '\n'.join(json.dumps(scrub_evidence(json.loads(line)), ensure_ascii=False)
                                  for line in lines) + '\n'
            except ValueError:
                pass
        # CLI envelopes may themselves be JSON strings inside capture fields.
        if value.lstrip().startswith(('{', '[')):
            try:
                return json.dumps(scrub_evidence(json.loads(value)), ensure_ascii=False)
            except ValueError:
                pass
        return value
    return value

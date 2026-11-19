"""Remove evaluator host/account metadata before publishing agent captures."""
from __future__ import annotations

import json
import re

_REMOVED = {'sessionid', 'uuid', 'messagingsocketpath', 'credentialexpiresat', 'memorypaths', 'accountuuid', 'accountid', 'organizationuuid', 'organizationid', 'oauthaccount'}


def scrub_evidence(value):
    if isinstance(value, dict):
        return {key: scrub_evidence(item) for key, item in value.items()
                if re.sub(r'[^a-z]', '', key.lower()) not in _REMOVED and 'plugin' not in key.lower()}
    if isinstance(value, list):
        return [scrub_evidence(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r'/private/var/folders/[^/\s"\\]+/[^/\s"\\]+/T', '/tmp/evaluator', value)
        value = re.sub(r'/Users/[^/\s"\\]+', '/home/evaluator', value)
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

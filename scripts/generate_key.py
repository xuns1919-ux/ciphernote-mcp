#!/usr/bin/env python3
"""Generate a CipherNote key without writing it to disk."""

import base64
import secrets

print("CIPHERNOTE_KEY=base64:" + base64.b64encode(secrets.token_bytes(32)).decode("ascii"))


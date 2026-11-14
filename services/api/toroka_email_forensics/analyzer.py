"""Compatibility shim: implementation moved to toroka_core.email_forensics.analyzer."""
import sys
from toroka_core.email_forensics import analyzer as _impl
sys.modules[__name__] = _impl

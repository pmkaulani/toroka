"""Compatibility shim: implementation moved to toroka_core.evidence.memory."""
import sys
from toroka_core.evidence import memory as _impl
sys.modules[__name__] = _impl

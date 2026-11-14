"""Compatibility shim: implementation moved to toroka_core.evidence.engine."""
import sys
from toroka_core.evidence import engine as _impl
sys.modules[__name__] = _impl

"""Compatibility shim: implementation moved to toroka_core.evidence.profile."""
import sys
from toroka_core.evidence import profile as _impl
sys.modules[__name__] = _impl

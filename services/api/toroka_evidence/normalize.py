"""Compatibility shim: implementation moved to toroka_core.evidence.normalize."""
import sys
from toroka_core.evidence import normalize as _impl
sys.modules[__name__] = _impl

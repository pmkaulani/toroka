"""Compatibility shim: implementation moved to toroka_core.evidence.provider_protocols."""
import sys
from toroka_core.evidence import provider_protocols as _impl
sys.modules[__name__] = _impl

"""Compatibility shim: implementation moved to toroka_core.evidence.scoring."""
import sys
from toroka_core.evidence import scoring as _impl
sys.modules[__name__] = _impl

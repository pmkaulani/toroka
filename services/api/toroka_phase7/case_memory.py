"""Compatibility shim: implementation moved to toroka_core.case_memory."""
import sys
from toroka_core import case_memory as _impl
sys.modules[__name__] = _impl

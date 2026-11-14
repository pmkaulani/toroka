"""Compatibility shim: implementation moved to toroka_core.timeline."""
import sys
from toroka_core import timeline as _impl
sys.modules[__name__] = _impl

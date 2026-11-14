"""Compatibility shim: implementation moved to toroka_core.evidence.models."""
import sys
from toroka_core.evidence import models as _impl
sys.modules[__name__] = _impl

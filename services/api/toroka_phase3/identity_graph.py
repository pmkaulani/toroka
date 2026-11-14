"""Compatibility shim: implementation moved to toroka_core.graph.identity_graph."""
import sys
from toroka_core.graph import identity_graph as _impl
sys.modules[__name__] = _impl

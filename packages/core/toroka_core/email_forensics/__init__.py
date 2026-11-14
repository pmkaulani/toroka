"""Local-first email forensics for Toroka. Raw messages are analyzed in memory only."""
from .analyzer import analyze_email

__all__ = ["analyze_email"]

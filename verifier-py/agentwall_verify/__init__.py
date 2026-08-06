"""An independent Python verifier for the AgentWall audit evidence format.

Written from docs/audit-format.md and nothing else. It shares no code with the
bundled TypeScript verifier, the Go verifier, or the Rust one, and it depends
on nothing outside the Python standard library, so agreement between them is
evidence about the format rather than about a shared runtime.
"""

__all__ = ["__version__"]

__version__ = "0.2.0"

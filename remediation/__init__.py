"""
remediation/
============
Phase 9 — Controlled Remediation & Safety subsystem.

Components:
    - safety_guard.py         : Strict allowlist validator and parameter sanitizer
    - action_executor.py      : Safe subprocess execution engine for approved actions
    - verification_engine.py  : Post-execution automated verification
    - rollback_engine.py      : Compensation command execution on verification failure
    - audit_logger.py         : Immutable hash-chained audit log
    - remediation_service.py  : Orchestration service tying all components together
"""

# Aegis Control Plane v1 — FROZEN

**Status:** FROZEN  
**Version:** v1  
**Freeze date:** 2026-09-23  
**Module:** Aegis.Diagnostics

This repository is part of the Aegis Control Plane v1 baseline.

The v1 control-plane design and behavior are frozen. Routine feature development must not alter the v1 baseline.

Post-freeze changes are limited to:
- critical security fixes;
- production defects;
- data-integrity or recovery defects;
- compatibility fixes required to keep the frozen behavior operational.

Any material new capability, workflow, UI behavior, contract change, or architecture change belongs in a post-v1 development line and must not silently redefine the v1 baseline.

The `v1-frozen` Git branch identifies the frozen snapshot for this module.

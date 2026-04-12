# Hardening & Prevention

This folder contains the hardening and prevention work for the Identity Security project.

The pages in this section document the defensive controls implemented in the lab to reduce identity attack exposure and improve resilience against common authentication-based threats. The focus is on applying security controls, validating that they work, and using telemetry to confirm the intended security outcome.

## Hardening Areas

### Windows LAPS Deployment
Documents the deployment of Windows LAPS to reduce local administrator password reuse and limit lateral movement opportunities.

**Documentation:** `laps-hardening.md`

---

### Kerberos Hardening
Documents Kerberos hardening measures used to reduce credential theft and offline cracking risk, including AES-only enforcement, preauthentication validation, and Kerberoasting exposure review.

**Documentation:** `kerberos-hardening.md`

---

## Hardening Methodology

Each hardening page is designed to document more than the control change alone. Where relevant, pages include:

- Control objective
- Configuration steps
- Validation method
- Supporting telemetry
- Security value of the control
- Notes on expected outcomes or regression indicators

## Notes

These pages are intended to show that identity security is not limited to detection and alerting. The emphasis is on reducing attack surface, validating control effectiveness, and linking preventive controls back to observable security telemetry.

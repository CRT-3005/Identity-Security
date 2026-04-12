# Dashboards

This folder contains the custom Splunk dashboards created for the Identity Security project.

The dashboards are designed to provide SOC-level visibility into authentication activity, Kerberos security posture, and indicators of identity abuse across the environment. Each dashboard supports detection validation, monitoring, and analyst-driven review rather than acting as a static visual only.

## Dashboard Areas

### Kerberos Security Posture Dashboard
Provides visibility into Kerberos service ticket activity, encryption posture, and Kerberoasting exposure.

**Documentation:** `kerberos-security-posture.md`

---

### Authentication Pressure Dashboard
Provides visibility into failed authentication pressure, source targeting, account targeting, and failed-to-successful authentication patterns.

**Documentation:** `authentication-pressure-dashboard.md`

---

## Dashboard Methodology

Each dashboard page is intended to document more than the finished visual. Where relevant, pages include:

- Dashboard purpose
- Panel-by-panel explanation
- Supporting SPL
- Time range decisions
- Analyst use case
- Validation notes

## Notes

These dashboards are designed to support operational monitoring and investigation in a SOC context. The emphasis is on helping analysts understand authentication behaviour, validate hardening controls, and spot suspicious identity activity more quickly.

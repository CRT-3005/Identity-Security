# SOC Playbooks

This folder contains the analyst playbooks used to support investigation and response across the Identity Security project.

The playbooks are written to reflect practical SOC handling after an alert fires. Each one focuses on how detections are validated, investigated, and escalated using authentication telemetry, enrichment queries, and identity context.

## Playbook Areas

### NTLM Password Spray Response
Documents the investigation and response workflow for suspected NTLM password spray activity.

**Documentation:** `ntlm-password-spray-playbook.md`

---

### Kerberos Password Spray Response
Documents the investigation and response workflow for suspected Kerberos password spray activity.

**Documentation:** `kerberos-password-spray-playbook.md`

---

## Playbook Methodology

Each playbook is intended to support repeatable analyst workflows rather than just describe the alert. Where relevant, pages include:

- Alert context
- Initial triage steps
- Investigation SPL
- Analyst decision points
- False positive checks
- Containment and remediation guidance
- MITRE ATT&CK mapping

## Notes

These playbooks are designed to show how identity detections are operationalised in a SOC setting. The focus is on practical investigation, consistent analyst decision-making, and linking detections to clear response actions.

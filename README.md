# Windows Attack Detection & Alerting with Splunk

A hands-on Security Operations Center (SOC) lab for detecting suspicious Windows activity using Sysmon telemetry, Splunk searches, and scheduled SIEM alerts.

## Overview

This project demonstrates an endpoint threat detection workflow in a controlled virtual environment. Windows activity is generated on a test machine, collected by Sysmon, forwarded to Splunk, and investigated using Search Processing Language (SPL).

The project focuses on building and validating detections, configuring alerts, and documenting the investigation process.

## Lab Architecture

**Windows 10 Endpoint → Sysmon → Splunk Universal Forwarder → Splunk Enterprise on Kali Linux**

- **Windows 10:** Generates endpoint activity for detection testing.
- **Sysmon:** Records selected Windows system and process events.
- **Splunk Universal Forwarder:** Sends collected events to the Splunk instance.
- **Kali Linux:** Hosts Splunk Enterprise for searching, detection, and alerting.


## Detection Scenarios

### 1. Suspicious PowerShell Execution

**Objective:** Identify PowerShell activity associated with system discovery.

**Test activity:** Run a controlled command that checks the current user and network configuration.

**Detection approach:** Search Windows telemetry in Splunk for relevant PowerShell command-line activity.

**Status:** Implemented and tested.

### 2. Scheduled SIEM Alerting

**Objective:** Automatically alert when the configured detection search returns matching events.

**Implementation:**
- Create a Splunk search for suspicious PowerShell activity.
- Schedule the search to run every five minutes.
- Configure the alert to trigger when results are found.
- Review the generated alert and matching events.

**Status:** Implemented and tested.

## Example Detection Search

```spl
index=* "powershell.exe" "whoami"
earliest=-5m@m latest=now
| table _time host source _raw
```

This example searches recent events for PowerShell and `whoami` text. It is a basic lab detection, not a definitive indicator of malicious activity. The search may need adjustment to match the index, event fields, and data sources in a different Splunk environment.

## Skills Demonstrated

- Windows endpoint monitoring
- Sysmon telemetry collection
- Splunk search and event investigation
- Basic SPL detection development
- Scheduled SIEM alert configuration
- Controlled attack simulation
- Alert validation and documentation
- Initial SOC alert triage

## Evidence

Screenshots and investigation notes are stored in the `screenshots/`, `detections/`, and `investigation/` directories.

## Limitations

This is a learning lab, not a production-ready detection platform. Current searches rely on text matching and may generate false positives or miss activity that uses different command syntax.

Future improvements include structured field extraction, narrower detection logic, alert deduplication, additional attack simulations, and investigation playbooks.

## Disclaimer

All testing is performed in an isolated, authorized virtual environment for educational and defensive security purposes.

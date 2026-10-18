# Suspicious PowerShell Activity Detection

## Overview

This detection identifies Windows events containing `powershell.exe` and the `whoami` command. These commands can appear during legitimate administration, but they can also be used during attacker reconnaissance to discover the identity and privileges of the current user.

**SIEM:** Splunk Enterprise  
**Log source:** Windows Event Logs collected with Sysmon and Splunk Universal Forwarder  
**Detection type:** Keyword-based event detection  
**Severity:** Low — requires investigation  
**MITRE ATT&CK:** [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)

## Objective

Detect potentially suspicious PowerShell-related activity and generate an alert that can be reviewed by a SOC analyst.

## Detection Logic

The search looks for events containing both `powershell.exe` and `whoami` within the previous hour.

```spl
index=* "powershell.exe" "whoami" earliest=-1h latest=now
| table _time host source _raw
```

### How It Works

- `index=*` searches across all accessible indexes.
- `"powershell.exe"` searches for the PowerShell executable name.
- `"whoami"` searches for the user-discovery command.
- `earliest=-1h latest=now` limits the search to the previous hour.
- `table` displays the event timestamp, host, source, and raw event.

## Alert Configuration

The saved search was configured to:

- Run every 5 minutes.
- Trigger when one or more results are returned.
- Add triggered events to Splunk's Triggered Alerts.

## Validation

The detection was tested by executing the following command in the Windows lab:

```powershell
powershell.exe -NoProfile -Command "whoami; ipconfig"
```

The test generated activity matching the search conditions, and the resulting alert was verified in Splunk.

## Limitations

This is a basic keyword-based detection, not proof of malicious activity. Legitimate administrators may execute the same command.

The rule also depends on the relevant event being collected and indexed. A production detection should use a dedicated index, more precise event fields, appropriate time windows, and additional context such as the process command line, parent process, user, and host.

## Analyst Response

When an alert fires:

1. Review the raw event and timestamp.
2. Identify the affected host and user.
3. Examine the full command line and parent process, if available.
4. Correlate the event with surrounding process and authentication activity.
5. Determine whether the activity is authorized or suspicious.
6. Document the findings and escalate when necessary.

**Important:** This detection identifies activity requiring review; it does not independently confirm a compromise.

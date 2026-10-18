# Splunk Detection Searches

## 1. Suspicious PowerShell and User Discovery

**Purpose:** Identify events containing PowerShell and the `whoami` command.

### SPL Query

```spl
index=* "powershell.exe" "whoami" earliest=-1h latest=now
| table _time host source _raw
```

### Search Parameters

| Parameter | Description |
|---|---|
| `index=*` | Search all accessible indexes |
| `powershell.exe` | Match the PowerShell executable name |
| `whoami` | Match user-discovery activity |
| `earliest=-1h` | Search from one hour ago |
| `latest=now` | End at the current time |
| `table` | Display selected event fields |

### Alert Settings

| Setting | Configuration |
|---|---|
| Schedule | Every 5 minutes |
| Trigger condition | Number of results greater than zero |
| Alert action | Add to Triggered Alerts |

### Test Command

```powershell
powershell.exe -NoProfile -Command "whoami; ipconfig"
```

### Expected Result

If the generated Windows event contains both search terms and is indexed within the selected time range, Splunk should return a matching event. The configured alert should trigger when the scheduled search finds results.

### Detection Limitations

- Keyword matching can produce false positives.
- Events may be missed if the relevant telemetry is not collected.
- Searching all indexes can be inefficient in a larger environment.
- This query does not establish malicious intent.

### Future Improvements

- Search a dedicated Windows event index.
- Filter on structured fields such as process image and command line.
- Correlate process creation events with parent process and user information.
- Add known-benign exclusions based on validated lab results.
- Build additional detections for encoded commands, suspicious downloads, and unusual PowerShell execution.

**Scope:** This repository documents a lab detection, not a production-ready detection pack.

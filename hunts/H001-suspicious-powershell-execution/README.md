# H001 - Suspicious PowerShell Execution on Windows

## Hypothesis

An attacker may use PowerShell on a Windows endpoint with suspicious command line flags to bypass restrictions, hide execution, download content, or execute code.

This hunt focuses on identifying suspicious PowerShell process creation using Sysmon Event ID 1 and validating script level activity with PowerShell Script Block Logging, typically recorded as PowerShell Event ID 4104.


## MITRE ATT&CK Mapping 

| Technique ID | Technique | 
| T1059.001 | Command and Scripting Interpreter: PowerShell |

This hunt maps to T1059.001 because the behaviour involves PowerShell being used to execute commands and scripts on a Windows endpoint.
- https://attack.mitre.org/techniques/T1059/001/


## Baseline Activity

Before testing suspicious behaviour, normal PowerShell activity was generated using common administrative commands such as `whoami`, `hostname`, `Get-Process`, `Get-Service`, and `Test-NetConnection`.

- Below Commands were run in CMD

**Commands:**

powershell.exe -NoProfile -Command "whoami"

powershell.exe -NoProfile -Command "hostname"

powershell.exe -NoProfile -Command "Get-Process | Select-Object -First 5"

powershell.exe -NoProfile -Command "Get-Service | Select-Object -First 5"

powershell.exe -NoProfile -Command "Test-NetConnection 192.168.37.129 -Port 9997"

- This helped establish what benign PowerShell execution looked like in the lab.



## Test Method

Safe manual PowerShell commands were executed on the Windows endpoint to generate suspicious looking telemetry without causing harm.

- Below Commands were run in CMD

**Commands:**

powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'H001 hidden PowerShell test'"

powershell.exe -NoProfile -Command "mkdir C:\Temp -Force; Invoke-WebRequest -Uri 'https://www.microsoft.com/favicon.ico' -OutFile 'C:\Temp\favicon.ico'"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'H001 suspicious PowerShell test'"


## Building Hunt to look for above Activity (Sysmon)

This Splunk query looks for PowerShell process creation events in Sysmon logs.
It flags suspicious PowerShell command lines, such as encoded commands, execution policy bypass, hidden windows, downloads, inline execution, or -NoProfile.
It then shows the time, host, user, parent process, PowerShell process, full command line, and the reason it was detected. 

SPL Query

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe" earliest=-30m
| eval cmd=lower(CommandLine)
| eval detection_reason=case(
    like(cmd,"%encodedcommand%") OR like(cmd,"%-enc%"), "Encoded command",
    like(cmd,"%executionpolicy bypass%"), "Execution policy bypass",
    like(cmd,"%windowstyle hidden%"), "Hidden window",
    like(cmd,"%downloadstring%") OR like(cmd,"%invoke-webrequest%"), "Download behaviour",
    like(cmd,"%iex%") OR like(cmd,"%invoke-expression%"), "Inline execution",
    like(cmd,"%-noprofile%"), "NoProfile flag",
    true(), "Other PowerShell"
)
| eval severity=case(
    detection_reason="Encoded command", "High",
    detection_reason="Download behaviour", "High",
    detection_reason="Inline execution", "High",
    detection_reason="Execution policy bypass", "Medium",
    detection_reason="Hidden window", "Medium",
    detection_reason="NoProfile flag", "Low",
    true(), "Informational"
)
| where detection_reason!="Other PowerShell"
| table _time host User ParentImage ParentCommandLine Image CommandLine detection_reason severity
| rename ParentImage as "Parent Process", ParentCommandLine as "Parent Command Line", Image as "Process", CommandLine as "Command Line", detection_reason as "Detection Reason", severity as "Severity"
| sort - _time
```
- Stores the CommandLine value in lowercase so the detection is case insensitive
- The case() function checks the command line against several suspicious patterns and assigns a detection label, as well as severity
- Used rename function to make fields easier to read and understand

**Results**

<img width="2293" height="529" alt="image" src="https://github.com/user-attachments/assets/c99cc47f-c207-413f-aaa1-98bf645ea42c" />

- The Sysmon hunt query successfully identified the generated PowerShell activity and categorised each event using the `detection_reason` field. As well as assigning a severity
- The `-NoProfile` flag was observed during testing; however, this is considered a low confidence indicator. It is commonly used by administrators, automation scripts, and deployment tooling to ensure PowerShell starts without loading user profile customisations. On its own, `-NoProfile` should not be treated as malicious and would likely be too noisy depending on the enviroment.
- This behaviour becomes more suspicious when combined with stronger indicators such as `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `EncodedCommand`, `IEX`, `DownloadString`, or unusual parent processes.

## PowerShell Event 4104 Validation (Looking at suspicious only)

SPL Query
```spl
index=powershell earliest=-30m
| rex "<EventID>(?<EventCode>\d+)</EventID>"
| rex "<Data Name='ScriptBlockText'>(?<ScriptBlockText>.*?)</Data>"
| search EventCode=4104
| eval script=lower(ScriptBlockText)
| eval detection_reason=case(
    like(script,"%encodedcommand%") OR like(script,"%-enc%"), "Encoded command",
    like(script,"%executionpolicy bypass%"), "Execution policy bypass",
    like(script,"%windowstyle hidden%"), "Hidden window",
    like(script,"%downloadstring%") OR like(script,"%invoke-webrequest%"), "Download behaviour",
    like(script,"%iex%") OR like(script,"%invoke-expression%"), "Inline execution",
    true(), "Other PowerShell"
)
| where detection_reason!="Other PowerShell"
| table _time host EventCode ScriptBlockText detection_reason
| sort - _time
```

- Used Regex to extract the Event code and ScriptBlockText as the fields were not parsed by default
- Using the same method of running the field which contains the command activity, through a case to assign a detection tag
- Then using Table to display the fields which were already parsed, as well as the manual field we created using regex "ScriptBlockText"

**Results**

<img width="2164" height="161" alt="image" src="https://github.com/user-attachments/assets/c51dcc10-93ef-43a3-8972-cd07db60dee9" />


- The download test is the only one was visible because the suspicious behaviour,`Invoke-WebRequest`, existed inside the script block content itself. Which is the specific field that the detection is looking at.


## PowerShell Event 4104 Validation (All Events)

```spl
index=powershell earliest=-30m
| rex "<EventID>(?<EventCode>\d+)</EventID>"
| rex "<Data Name='ScriptBlockText'>(?<ScriptBlockText>.*?)</Data>"
| search EventCode=4104
| eval script=lower(ScriptBlockText)
| eval detection_reason=case(
    like(script,"%encodedcommand%") OR like(script,"%-enc%"), "Encoded command",
    like(script,"%executionpolicy bypass%"), "Execution policy bypass",
    like(script,"%windowstyle hidden%"), "Hidden window",
    like(script,"%downloadstring%") OR like(script,"%invoke-webrequest%"), "Download behaviour",
    like(script,"%iex%") OR like(script,"%invoke-expression%"), "Inline execution",
    true(), "Other PowerShell"
)
| where like(script,"%h001%")
    OR like(script,"%write-output%")
    OR like(script,"%invoke-webrequest%")
    OR like(script,"%mkdir c:\\temp%")
    OR like(script,"%whoami%")
    OR like(script,"%hostname%")
    OR like(script,"%get-process%")
    OR like(script,"%get-service%")
    OR like(script,"%test-netconnection%")
| table _time host EventCode ScriptBlockText detection_reason
| sort - _time
```

**Results**

<img width="2295" height="288" alt="image" src="https://github.com/user-attachments/assets/9c52a3d5-f3cc-4efb-b633-d5b2ac64d70f" />

- Here is clear evidence that powershell 4104 is simply looking at the script content and not the whole command context like sysmon, no flags are included. This is expected activity
- When the `Other PowerShell` events were included, PowerShell Event ID 4104 showed related script block activity such as the `Write-Output` test commands. These were not labelled as suspicious by the 4104 detection logic because the suspicious launch flags were present in the process command line captured by Sysmon, not necessarily inside the script block content captured by 4104.


## Lessons Learned & Findings

The hunt identified PowerShell executions containing suspicious command line patterns such as -NoProfile, -ExecutionPolicy Bypass, -WindowStyle Hidden, and download related behaviour.

Sysmon Event ID 1 is useful for identifying PowerShell process creation, including parent child process relationships and the command line used when PowerShell is launched.

PowerShell Event ID 4104 provides deeper script block visibility and can show commands processed or executed inside PowerShell, including activity that may not appear as a new process creation event.

Combining Sysmon process creation telemetry with PowerShell script block logging provides stronger investigative context than relying on either source alone.

In this specific test case, Sysmon alone was enough to understand the activity because the suspicious PowerShell behaviour was visible directly in the command line. 

**Summary:**

PowerShell Event ID 4104 = Shows PowerShell script block content processed by PowerShell.

Sysmon Event ID 1 = Shows process creation, including how PowerShell was launched and the command line used at launch time.

In this lab, the commands were run from cmd.exe, which called powershell.exe and passed a command to it. This created a new PowerShell process each time, triggering a new Sysmon Event ID 1 event for each launch.


### Additional Observation

PowerShell Event ID 4104 behaviour can differ depending on how the command is executed.

When PowerShell is launched from cmd.exe, Sysmon Event ID 1 captures the full PowerShell process command line, including launch arguments such as -NoProfile, -ExecutionPolicy Bypass, and -WindowStyle Hidden.

When a new powershell.exe process is launched from inside an existing PowerShell session, PowerShell Event ID 4104 may also capture the full command typed into the parent PowerShell session. In that case, the launch flags may appear in 4104 as script block content.

However, when commands are run directly inside an already existing PowerShell session, there may be no new PowerShell process launch and therefore no launch flags for Sysmon Event ID 1 to capture. In that case, PowerShell Event ID 4104 is more useful for showing the script content that was executed, while Sysmon Event ID 1 remains more useful for process creation and parent child process understanding. 
  

**Note:** Security event 4688 is another good one to check however its Less rich than Sysmon and command line must be separately enabled via policy. Enabling Sysmon provides more powerful process telemetry, but combining sysmon and powershell event 4104 seems to be the most powerful combination. 

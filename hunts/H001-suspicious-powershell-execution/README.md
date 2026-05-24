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

This helped establish what benign PowerShell execution looked like in the lab.



## Test Method

Safe manual PowerShell commands were executed on the Windows endpoint to generate suspicious looking telemetry without causing harm.

**Commands:**

powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output 'H001 hidden PowerShell test'"

powershell.exe -NoProfile -Command "mkdir C:\Temp -Force; Invoke-WebRequest -Uri 'https://www.microsoft.com/favicon.ico' -OutFile 'C:\Temp\favicon.ico'"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'H001 suspicious PowerShell test'"


## Building Hunt to look for above Activity

This Splunk query looks for PowerShell process creation events in Sysmon logs.
It flags suspicious PowerShell command lines, such as encoded commands, execution policy bypass, hidden windows, downloads, inline execution, or -NoProfile.
It then shows the time, host, user, parent process, PowerShell process, full command line, and the reason it was detected. 

- Stores the CommandLine value in lowercase so the detection is case insensitive
- The case() function checks the command line against several suspicious patterns and assigns a label.
- Used rename function to make fields easier to read and understand

SPL Query

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
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
| where detection_reason!="Other PowerShell"
| table _time host User ParentImage Image CommandLine detection_reason
| rename ParentImage as "Parent Process", Image as "Process", CommandLine as "Command Line"
```

**Results**

<img width="2299" height="478" alt="image" src="https://github.com/user-attachments/assets/4d66b2e5-9c97-41fd-a8a4-3240ca55f36d" />


- The Sysmon hunt query successfully identified the generated PowerShell activity and categorised each event using the `detection_reason` field.
- The `-NoProfile` flag was observed during testing; however, this is considered a low confidence indicator. It is commonly used by administrators, automation scripts, and deployment tooling to ensure PowerShell starts without loading user profile customisations. On its own, `-NoProfile` should not be treated as malicious and would likely be too noisy depending on the enviroment.
- This behaviour becomes more suspicious when combined with stronger indicators such as `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `EncodedCommand`, `IEX`, `DownloadString`, or unusual parent processes.

## PowerShell Event 4104 Validation

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
```

- Used Regex to extract the Event code and ScriptBlockText as the fields were not parsed by default
- Using the same method of running the field which contains the command activity, through a case to assign a detection tag
- Then using Table to display the fields which were already parsed, as well as the manual field we created using regex "ScriptBlockText"

**Results**

<img width="2275" height="178" alt="image" src="https://github.com/user-attachments/assets/6515c749-b601-422f-b69c-0263d1623609" />



## Lessons Learned & Findings

The hunt identified PowerShell executions containing suspicious commandline patterns such as `-NoProfile`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, and download-related behaviour.

Sysmon Event ID 1 is useful for identifying PowerShell process creation and command line arguments at launch time.

Commands typed inside an already running PowerShell session may not always appear as new Sysmon Event ID 1 events unless they spawn a new process.

PowerShell Event ID 4104 provides deeper script block visibility and can show commands executed inside PowerShell.

Combining Sysmon process creation telemetry with PowerShell script block logging provides stronger investigative context than relying on either source alone.

In this specific test case, Sysmon alone was enough to understand the activity because the suspicious PowerShell behaviour was visible directly in the command line.

**Summary:**

**PowerShell Event 4104** = What code ran inside PowerShell In General

**Sysmon Event 1** = Shows how PowerShell was launched and includes the command line used at the time the PowerShell process was created.
- For e.g, in this lab, the commands were run from CMD, which called powershell.exe and passed a command to it. This created a new PowerShell process each time, which triggered a new Sysmon Event ID 1 for each PowerShell launch.


**Note:** Security event 4688 is another good one to check however its Less rich than Sysmon and command line must be separately enabled via policy. Enabling Sysmon provides more powerful process telemetry, but combining sysmon and powershell event 4104 seems to be the most powerful combination. 

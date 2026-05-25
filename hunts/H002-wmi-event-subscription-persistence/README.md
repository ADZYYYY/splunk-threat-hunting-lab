# H002 - WMI Event Subscription Persistence

## Hypothesis

An attacker may create a permanent WMI event subscription to maintain persistence on a Windows endpoint.

This technique can involve creating three WMI components:

- An event filter, which defines the trigger condition
- An event consumer, which defines the action to execute
- A filter-to-consumer binding, which links the trigger to the action


## MITRE ATT&CK Mapping

| Technique ID | Technique |
| T1546.003 | Event Triggered Execution: Windows Management Instrumentation Event Subscription |

This hunt maps to MITRE ATT&CK `T1546.003` because WMI event subscriptions can be used to execute commands automatically when a defined WMI event condition is met.

- https://attack.mitre.org/techniques/T1546/003/


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

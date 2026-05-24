# H001 - Suspicious PowerShell Execution on Windows

## Hypothesis

An attacker may use PowerShell on a Windows endpoint with suspicious command line flags to bypass restrictions, hide execution, download content, or execute code.

This hunt focuses on identifying suspicious PowerShell process creation using Sysmon Event ID 1 and validating script level activity with PowerShell Script Block Logging, typically recorded as PowerShell Event ID 4104.


## MITRE ATT&CK Mapping 

| Technique ID | Technique | 
| T1059.001 | Command and Scripting Interpreter: PowerShell |

This hunt maps to T1059.001 because the behaviour involves PowerShell being used to execute commands and scripts on a Windows endpoint.
- https://attack.mitre.org/techniques/T1059/001/


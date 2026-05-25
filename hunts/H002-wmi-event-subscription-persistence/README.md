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


## Test Method

## T1546.003-1: Persistence via WMI Event Subscription - CommandLineEventConsumer

This test uses Atomic Red Team technique **T1546.003** to simulate persistence through a **WMI Event Subscription** using a `CommandLineEventConsumer`. 

I Ran the test with the below (Required installing atomic red prereq):

```powershell
Invoke-AtomicTest T1546.003 -TestNumbers 1 -PathToAtomicsFolder C:\AtomicRedTeam\atomics
```



## Hunting for WMI Persistence with Sysmon

```spl
index=sysmon earliest=-30m (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval wmi_event_type=case(
    EventCode=19, "WMI Event Filter Created",
    EventCode=20, "WMI Event Consumer Created",
    EventCode=21, "WMI Filter-to-Consumer Binding Created",
    true(), "Other WMI Event"
)
| table _time host User EventCode wmi_event_type RuleName Name Query Consumer CommandLineTemplate Destination
| rename wmi_event_type as "WMI Event Type", CommandLineTemplate as "Command Line Template"
| sort _time
```
-  Searching Sysmon endpoint telemetry.
- `(EventCode=19 OR EventCode=20 OR EventCode=21)` filters for WMI event subscription activity. 
- `case()` assigns a readable label to each WMI event type.
- `table` used to display the fields needed to understand the WMI persistence components.
- `sort _time` orders the events chronologically so the persistence chain can be reviewed in sequence.#
- Also used rename to help with readability 

**Results**

![Sysmon WMI](screenshots/sysmonWMIPersistenceH002.png)

- This data provides key information about the WMI persistence mechanism, including the creation time, creator, event filter trigger logic, and the associated event consumer. The consumer is particularly important as it defines the action to execute, such as running a command or launching a payload when the filter condition is triggered.
- **Note**: The Sysmon `RuleName` field mapped the activity to `T1047 - Windows Management Instrumentation`. This reflects the use of WMI.
For this hunt, the behaviour is mapped to `T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription` because the activity specifically involved creating a persistent WMI event subscription made up of a filter, consumer, and binding
 

**Event Filter AKA Trigger**
```
"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime &gt;= 240 AND TargetInstance.SystemUpTime &lt; 325"
```
- This WMI query monitors system uptime and triggers when the machine has been running for between 240 and 325 seconds, which is roughly 4 to 5 minutes after startup. When this condition is met, the linked WMI Event Consumer is executed. 

**Event Consumer**

```
Destination "C:\\WINDOWS\\System32\\notepad.exe"
```
- In this scenario, notepad.exe is the payload configured within the WMI Event Consumer.
- notepad.exe is used here as a safe demonstration payload. In a real intrusion, the consumer could be configured to execute a malicious script, malware payload, reverse shell, or typically, utilizing LOLBINS when the WMI filter condition is triggered.
 
**WMI Filter-to-Consumer Binding Created**

- The Filter-to-Consumer Binding links the filter logic and the consumer action together.
- Without the binding, the filter may still detect that the condition is met, and the consumer may still contain the command to run, but nothing connects them together.






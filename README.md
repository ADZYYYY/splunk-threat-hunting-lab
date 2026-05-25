## Splunk Threat Hunting Lab

This repository documents my hands on threat hunting and detection engineering lab.

## Goal

Build a practical home lab for learning threat hunting, Windows telemetry and detection engineering using Splunk, Sysmon, and Atomic Red Team.

## Current Lab Stack

- Splunk Enterprise Free (Using Splunk Addons for Sysmon and Windows to help with parsing out fields)
- Ubuntu Server (Hosting Splunk Enterprise)
- Windows 11 Enterprise Evaluation (Victim Machine)
- Splunk Universal Forwarder (Configured on Victim machine to send logs to Ubuntu Server)
- Sysmon with Olaf Hartong's Sysmon Modular config (https://github.com/olafhartong/sysmon-modular)
- MITRE ATT&CK mapping from Olaf Hartong’s Sysmon config
- Atomic Red Team for simulating threat actors (https://github.com/redcanaryco/atomic-red-team/tree/master)

## Planned Hunts

- H001 - Suspicious PowerShell Execution
- H002 - Account Discovery
- H003 - Scheduled Task Persistence
- H004 - Registry Run Key Persistence
- H005 - Suspicious Download Tools

## Purpose

The purpose of this repository is to document my learning, detections, lab setup, SPL queries, and threat hunting methodology as I develop deeper skills in incident response, threat hunting, detection engineering, and security automation.

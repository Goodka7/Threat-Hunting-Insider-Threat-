<img width="400" src="https://github.com/user-attachments/assets/c741101c-04f7-4115-90f3-77d677585dbd"/>

# Threat Hunt Report: Unauthorized Persistence & Backdoor Creation

## Platforms and Languages Leveraged
- Linux (Ubuntu 22.04) Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Bash

## Scenario

Management has raised concerns about a recent rise in threat actors targeting outdated software with known vulnerabilities, which could compromise company systems. These vulnerabilities are often exploited through outdated versions of software that employees may still be using, whether knowingly or unknowingly. Security teams have detected that several internal machines may be running outdated software, and there's a risk that these versions could be exploited by malicious actors. Management has requested a comprehensive review to identify and confirm any instances of outdated software in use across the organization.

The objective is to detect and analyze the usage of outdated software with known vulnerabilities, assess the potential security risks across multiple systems, and ensure that all software being used within the organization is up to date and secure.

### High-Level IoC Discovery Plan

- **Check `DeviceFileEvents`** for modifications to `~/.ssh/authorized_keys`, systemd service files, and SUID binaries.
- **Check `DeviceProcessEvents`** for suspicious executions, including unauthorized system service modifications and Trojanized commands.
- **Check `DeviceLogonEvents`** for unusual remote login activity.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table for SUID Backdoor Creation & Execution

Identify unauthorized privilege escalation attempts and backdoor persistence through SUID manipulation.

At **Feb 2, 2025 1:33:49 PM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
sh -c 'cat /proc/sys/kernel/random/uuid | awk -F- '{print $1$2$3$4$5}''
```

This command is commonly used to generate a unique identifier, possibly as part of a script used to automate privilege escalation or persistence.

At **Feb 2, 2025 3:54:17 PM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
sudo chown root:root /tmp/rootbash
```

Shortly after, at 3:55:22 PM, the user set the SUID permission to ensure persistent root access:
```
sudo chmod u+s /tmp/rootbash
```

Finally, at Feb 2, 2025 3:56:18 PM, the attacker executed:
```
/tmp/rootbash -p
```

This confirms the successful execution of the backdoor, allowing privilege escalation to root.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ProcessCommandLine contains "authorized_keys" or ProcessCommandLine contains "echo" or ProcessCommandLine contains "cat"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine

DeviceProcessEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ProcessCommandLine contains "/tmp/rootbash"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/3c1fabbb-7fc1-4978-a99c-763d777dc109">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/cae6aeea-aa55-45e2-b0e4-e5d8b896dd84">

---

### 2. Searched the `DeviceLogonEvents` Table

Searched for any `AccountName` that was not "baddog" to detect unauthorized SSH logins.

At **Feb 2, 2025 3:15:01 PM**, the user **"root"** logged into the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** via **Network logon type**, indicating a remote SSH connection.

This suggests that a backdoor mechanism was used to gain unauthorized root access.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where AccountName != "baddog"  // Look for unexpected SSH logins
| where LogonType in ("RemoteInteractive", "Network")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/c6eb0196-2d43-4f1f-bd9a-8b7acf6862cd">

---

### 3. Searched the `DeviceProcessEvents` Table for Malicious Systemd Service Execution

**Objective:** Detect the creation or execution of a malicious systemd service for persistence.

At **Feb 2, 2025 3:12:10 PM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
sudo systemctl start malicious.service
```

This action started a malicious systemd service designed to maintain persistent access to the system.

The service was created earlier by the user with the following command:
```
sudo nano /etc/systemd/system/malicious.service
```

This confirms that the systemd service malicious.service was set up as a means of ensuring the attacker could regain access if necessary.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ProcessCommandLine contains "malicious.service"
| project Timestamp, DeviceName, ActionType, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/bab374b0-e90b-4c57-9689-a24fb506bf49">

---

### 4. Searched the `DeviceProcessEvents` Table for Trojanized `ls` Execution

**Objective:** Detect the execution of a Trojanized script (`ls`) used to maintain unauthorized access.

At **Feb 2, 2025 4:00:13 PM**, the user **"baddog"** executed the following command on the device **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"**:
```
~/.local/bin/ls
```
This command runs a Trojanized version of the `ls` utility, which was replaced by a script that attempts to establish a reverse shell connection back to the attacker's machine. This action indicates the attempt to maintain access by running malicious scripts under the guise of a common administrative command.

**Query used to locate events:**

```kql
// Detect execution of Trojanized 'ls' command
DeviceProcessEvents
| where DeviceName == "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where ProcessCommandLine contains "/home/baddog/.local/bin/ls"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine 
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/505f75e4-e504-4865-87d9-1289d69ee748">

---

## Chronological Event Timeline 

### 1. File Download - SUID Backdoor Binary

- **Time:** `Feb 2, 2025 3:54:17 PM`
- **Event:** The user "baddog" downloaded and created a malicious backdoor binary (`/tmp/rootbash`) to be used for privilege escalation.
- **Action:** File creation detected.
- **File Path:** `/tmp/rootbash`

### 2. Process Execution - Privilege Escalation Attempt

- **Time:** `Feb 2, 2025 3:54:17 PM`
- **Event:** The user "baddog" executed the command `sudo chown root:root /tmp/rootbash` to set the ownership of the `/tmp/rootbash` binary to root for privilege escalation.
- **Action:** Process creation detected.
- **Command:** `sudo chown root:root /tmp/rootbash`
- **File Path:** `/tmp/rootbash`

### 3. Process Execution - Setting SUID on Backdoor Binary

- **Time:** `Feb 2, 2025 3:55:22 PM`
- **Event:** The user "baddog" executed the command `sudo chmod u+s /tmp/rootbash` to set the SUID on the backdoor binary, ensuring any user who executes it would gain root privileges.
- **Action:** Process creation detected.
- **Command:** `sudo chmod u+s /tmp/rootbash`
- **File Path:** `/tmp/rootbash`

### 4. Process Execution - SUID Backdoor Execution

- **Time:** `Feb 2, 2025 3:56:18 PM`
- **Event:** The user "baddog" executed the SUID backdoor binary `/tmp/rootbash`, confirming the escalation of privileges to root.
- **Action:** Process execution detected.
- **Command:** `/tmp/rootbash -p`
- **File Path:** `/tmp/rootbash`

### 5. Additional Privilege Escalation Attempts

- **Time:** `Feb 2, 2025 3:57:45 PM`
- **Event:** The user "baddog" executed additional processes related to privilege escalation, confirming continued use of the SUID backdoor for root access.
- **Action:** Process execution detected.
- **Command:** `/tmp/rootbash`
- **File Path:** `/tmp/rootbash`

### 6. File Creation - Malicious Systemd Service

- **Time:** `Feb 2, 2025 3:59:50 PM`
- **Event:** The user "baddog" created a malicious systemd service called `malicious.service` to ensure persistent access through service execution.
- **Action:** File creation detected.
- **File Path:** `/etc/systemd/system/malicious.service`

### 7. Process Execution - Starting Malicious Systemd Service

- **Time:** `Feb 2, 2025 4:01:30 PM`
- **Event:** The user "baddog" executed the command `sudo systemctl start malicious.service`, activating the malicious service to ensure the backdoor remains running.
- **Action:** Process execution detected.
- **Command:** `sudo systemctl start malicious.service`
- **File Path:** `/etc/systemd/system/malicious.service`

### 8. File Creation - Trojanized `ls` Command

- **Time:** `Feb 2, 2025 4:05:42 PM`
- **Event:** The user "baddog" created a Trojanized version of the `ls` command at `/home/baddog/.local/bin/ls`, which was used to maintain persistent access by executing a reverse shell upon being run.
- **Action:** File creation detected.
- **File Path:** `/home/baddog/.local/bin/ls`

### 9. Process Execution - Trojanized `ls` Command Execution

- **Time:** `Feb 2, 2025 4:06:05 PM`
- **Event:** The user "baddog" executed the Trojanized `ls` command, which established a reverse shell connection back to the attacker's machine.
- **Action:** Process execution detected.
- **Command:** `/home/baddog/.local/bin/ls`
- **File Path:** `/home/baddog/.local/bin/ls`

### 10. Additional SUID Backdoor Execution

- **Time:** `Feb 2, 2025 4:10:20 PM`
- **Event:** The user "baddog" executed `/tmp/rootbash` again to confirm privilege escalation, ensuring continued root access on the system.
- **Action:** Process execution detected.
- **Command:** `/tmp/rootbash -p`
- **File Path:** `/tmp/rootbash`

---

## Summary

The user "baddog" on the device "thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net" took deliberate actions to establish persistence and gain unauthorized root access. Initially, the attacker created a malicious backdoor binary (`/tmp/rootbash`) and modified its ownership to `root`. Following this, the attacker set the SUID permission on the binary, allowing any user to execute it with root privileges, effectively escalating their access. The attacker then executed the backdoor to confirm the privilege escalation.

To ensure persistent access, the attacker created and enabled a **malicious systemd service** (`malicious.service`) which would automatically start the backdoor on system boot. Additionally, a **Trojanized `ls` command** was placed in the user's home directory (`~/.local/bin/ls`), which was executed to establish a reverse shell connection back to the attacker's machine.

These actions suggest that the user "baddog" was attempting to establish a **backdoor and maintain persistent root access** on the system, bypassing security controls and potentially preparing for further unauthorized activities.

---

## Response Taken

Unauthorized root access and backdoor activities were confirmed on the endpoint **"thlinux.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"** by the user **"baddog"**. The device was isolated, the backdoor and associated persistence mechanisms were disabled, and the user's direct manager was notified. Further investigation and remediation are underway to assess any potential data exfiltration or other malicious actions.

---

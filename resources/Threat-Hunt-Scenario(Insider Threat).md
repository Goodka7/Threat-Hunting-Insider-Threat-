# Threat Event (Unauthorized Software Download)

## Steps the "Bad Actor" took to Create Logs and IoCs:

1. Download the outdated version of vulnerable software (e.g., **Apache**, **OpenSSL**, **FTP server**).
2. Install the outdated software silently:
`tar -xzvf apache-2.4.39.tar.gz
./configure --prefix=/usr/local/apache2
make
sudo make install`
3. Run the outdated software and start the service to verify its functionality: `sudo /usr/local/apache2/bin/apachectl start`

## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Used to detect execution of Trojanized commands, privilege escalation attempts, and service creation. |

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceFileEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose** | Used to detect the creation and modification of system files, including systemd services and backdoor binaries. |

| **Parameter** | **Description** |
|--------------|----------------|
| **Name** | DeviceLogonEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table |
| **Purpose** | Used to detect unauthorized remote logins or unusual authentication patterns. |

---

## Related Queries:

```kql
// Detect execution of a Trojanized administrative command
DeviceProcessEvents
| where ProcessCommandLine contains "ls"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect execution of a SUID backdoor shell
DeviceProcessEvents
| where ProcessCommandLine contains "rootbash"
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect potential unauthorized logins
DeviceLogonEvents
| where AccountName contains "root"
| where LogonType in ("RemoteInteractive", "Interactive")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```

---

## Created By:
- **Author Name**: James Harrington
- **Author Contact**: https://www.linkedin.com/in/Goodk47
- **Date**: January 30, 2025

## Validated By:
- **Reviewer Name**:
- **Reviewer Contact**:
- **Validation Date**:

---

## Additional Notes:
**None**

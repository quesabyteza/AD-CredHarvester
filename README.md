# Find-ExposedADPasswords.ps1

A robust PowerShell script for enumerating Active Directory environments for exposed credentials and misconfigurations.

## 🔍 Features

- Search user/computer/group descriptions for password strings
- Extract GPP cpasswords from SYSVOL
- Scan login scripts in NETLOGON
- Attempt LAPS credential extraction
- Designed for internal lab/pentest use

## 🚀 Usage

```powershell
.\Find-ExposedADPasswords.ps1
```

Requires `ActiveDirectory` module and domain access. Run from a PowerShell terminal with appropriate privileges.

## ⚠️ Disclaimer

This tool is for educational and authorized penetration testing **only**. Unauthorized use may violate laws and ethical standards.

## 👤 Author

Created by Michael van staden

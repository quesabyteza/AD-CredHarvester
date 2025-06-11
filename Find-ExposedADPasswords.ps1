
<#
.SYNOPSIS
    Enumerates Active Directory and common shared locations for plaintext or weakly protected credentials.

.DESCRIPTION
    This script helps penetration testers and red teamers quickly identify areas within an AD environment where
    passwords may be stored in plaintext or weakly protected formats, including AD attributes, GPP files, and login scripts.

.NOTES
    Author: Michael Van Staden
    License: MIT
    Intended for educational and authorized use only.
#>

function Search-ADUserDescriptions {
    Write-Host "`n[+] Searching AD user descriptions..." -ForegroundColor Cyan
    Get-ADUser -Filter * -Properties Description | Where-Object {
        $_.Description -match 'password|pass|pwd'
    } | Select-Object Name, SamAccountName, Description
}

function Search-ADUserInfo {
    Write-Host "`n[+] Searching AD user info fields..." -ForegroundColor Cyan
    Get-ADUser -Filter * -Properties Info | Where-Object {
        $_.Info -match 'password|pass|pwd'
    } | Select-Object Name, SamAccountName, Info
}

function Search-ADComputerDescriptions {
    Write-Host "`n[+] Searching computer descriptions..." -ForegroundColor Cyan
    Get-ADComputer -Filter * -Properties Description | Where-Object {
        $_.Description -match 'password|pass|pwd'
    } | Select-Object Name, Description
}

function Search-ADGroupDescriptions {
    Write-Host "`n[+] Searching AD group descriptions..." -ForegroundColor Cyan
    Get-ADGroup -Filter * -Properties Description | Where-Object {
        $_.Description -match 'password|pass|pwd'
    } | Select-Object Name, Description
}

function Search-GPPPasswords {
    Write-Host "`n[+] Scanning SYSVOL for GPP cpassword entries..." -ForegroundColor Cyan
    $sysvolPath = "\$env:USERDOMAIN\SYSVOL"
    Try {
        Get-ChildItem -Recurse -Path $sysvolPath -Include *.xml -ErrorAction Stop | ForEach-Object {
            Select-String -Path $_.FullName -Pattern "cpassword|password" -SimpleMatch
        }
    } Catch {
        Write-Warning "[-] Could not access SYSVOL. Check permissions and domain connectivity."
    }
}

function Search-NetlogonScripts {
    Write-Host "`n[+] Scanning NETLOGON scripts for plaintext credentials..." -ForegroundColor Cyan
    $netlogonPath = "\$env:USERDOMAIN\NETLOGON"
    Try {
        Get-ChildItem -Recurse -Path $netlogonPath -Include *.bat, *.ps1, *.vbs -ErrorAction Stop | ForEach-Object {
            Select-String -Path $_.FullName -Pattern "password|pass|pwd|creds|key"
        }
    } Catch {
        Write-Warning "[-] Could not access NETLOGON share."
    }
}

function Search-LAPSCredentials {
    Write-Host "`n[+] Checking for LAPS passwords..." -ForegroundColor Cyan
    Try {
        Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | Where-Object {
            $_.'ms-Mcs-AdmPwd'
        } | Select-Object Name, 'ms-Mcs-AdmPwd'
    } Catch {
        Write-Warning "[-] Cannot view LAPS passwords or LAPS not deployed."
    }
}

function Run-CredentialHunt {
    Search-ADUserDescriptions
    Search-ADUserInfo
    Search-ADComputerDescriptions
    Search-ADGroupDescriptions
    Search-GPPPasswords
    Search-NetlogonScripts
    Search-LAPSCredentials

    Write-Host "`n[!] Done. Review output for potential password disclosures." -ForegroundColor Green
}

Run-CredentialHunt

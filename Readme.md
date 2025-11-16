# Incident Response Lab

This lab is a report/walkthrough of the <a href="https://blueteamlabs.online/home/investigation/bec-ky-d75e02a0dd">'Bec-ky'</a> lab from Blue Team Labs Online. The purpose of this lab is to investigate an email phishing case to track changes made shown in Azure logs.
__________________________________________________________________________________________________________________________________________________________________________

## Tools Used
- Powershell
- Azure
- MXToolbox/MX lookup tool within Mozilla Thunderbird
___________________________________________________________________________________________________________________________________

## Lab Walkthrough with Screenshots


![image](https://github.com/user-attachments/assets/cb686be1-1985-45d6-805a-edddaa6d9aff)

<img width="1347" height="1110" alt="image" src="https://github.com/user-attachments/assets/e5616582-3a25-4c07-8d05-895657e843a3" />

<img width="901" height="856" alt="image" src="https://github.com/user-attachments/assets/a65bcc3b-2d40-4e7b-9715-55bcdd960c05" />

<img width="1963" height="664" alt="image" src="https://github.com/user-attachments/assets/ddef8e67-6333-4367-b0bb-628717253510" />

<img width="1884" height="541" alt="image" src="https://github.com/user-attachments/assets/2ae0884a-91f1-4af2-a870-46f0d531b9c3" />


Powershell script to filter for IP address and operations
```
Import-Csv .\azure-export-audit-dfir.csv |
  ForEach-Object {
    if ($_.AuditData -match '"ClientIP":"(\d{1,3}(\.\d{1,3}){3})”') {
        [PSCustomObject]@{
            CreationDate = $_.CreationDate
            Operation    = $_.Operation
            UserId       = $_.UserId
            ClientIP     = $matches[1]
        }
    }
  } | Sort-Object CreationDate | Format-Table -AutoSize

```

# Incident Response Lab

This lab is a report/walkthrough of the <a href="https://blueteamlabs.online/home/investigation/bec-ky-d75e02a0dd">'Bec-ky'</a> lab from Blue Team Labs Online. The purpose of this lab is to investigate an email phishing case by tracking changes made shown in Azure logs and looking into MX data of the emails.
__________________________________________________________________________________________________________________________________________________________________________

## Tools Used
- Powershell
- Azure
- MXToolbox/MX lookup tool within Mozilla Thunderbird
___________________________________________________________________________________________________________________________________

## Lab Walkthrough with Screenshots

First, I checked the emails provided in the Artefacts folder. The email file that stood out the most was the one labled: (No Subject).  

<img width="506" height="155" alt="image" src="https://github.com/user-attachments/assets/6a562f7e-4ffd-43b9-81dd-69b92acbb2f7" />

There are a couple red flags about the link in this email and a few other red flags about the email itself. The link has copilotweb.co as the top level domain which does not coincide with the true top level domain for copilot, which is microsoft.com or microsoftonline.com. Secondly, it directs specifically to GuKdDmBu. While having GuKdDmBu isn't inherently malicious, having it be at the end of the link to direct to a specific part of the copilotweb.co domain along with the previous issue, sets off major alarm bells. The email itself also contains wording about "early-access rollout for selected organisations" which suggests the potential of missing out on a limited opportunity enticing the user to click the link.

<img width="687" height="352" alt="image" src="https://github.com/user-attachments/assets/e093cc29-addf-4af0-97a5-f68fc6ddde95" />

This answers the first question of the lab: What is the source address of the initial phishing email?

sabastian@flanaganspensions.co.uk

And by happenstance, this also answers the second question: What type of compromise is this?

Business Email Compromise

Below is a screenshot of the Azure logs available to search through to find the rest of the answers to the questions. The next questions being: What are the two IPs utilised by the TA?

![image](https://github.com/user-attachments/assets/cb686be1-1985-45d6-805a-edddaa6d9aff)

Now, there are 1000+ individual events in this log file which is way way too many to go through one by one to find anything amiss. Even narrowing down the list to just events that happened on 2025-07-02 at 3PM, still gives us 217. To help format data into a more digestible form, I used the powershell script below.
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

Now using the time listed in the MX data of the phishing email and the formatted data in the screenshots below, there are 2 IP addresses that show up after the phishing email is received that did not previously show up.

159.203.17.81 and 95.181.232.30

<img width="970" height="167" alt="image" src="https://github.com/user-attachments/assets/8944abd9-d15b-47d2-8dfa-1080675b33e2" />
<img width="1347" height="1110" alt="image" src="https://github.com/user-attachments/assets/e5616582-3a25-4c07-8d05-895657e843a3" />

Next, we are tasked with finding which bank the transaction was sent to. We find the answer in another email provided in the Artefacts folder: FBNINGLA. This bank code belongs to the First Bank of Nigeria Ltd.

<img width="901" height="856" alt="image" src="https://github.com/user-attachments/assets/a65bcc3b-2d40-4e7b-9715-55bcdd960c05" />

Finally, we are tasked with finding both a folder created in the Inbox folder and a rule created for the Inbox prior to deleting emails. To do this I just searched all of the logs for "rule". A lot less visually easy on the eyes as the previous method of narrowing the search pool, but it works by only finding rule 12 times among all of the logs as shown below.

<img width="1884" height="541" alt="image" src="https://github.com/user-attachments/assets/2ae0884a-91f1-4af2-a870-46f0d531b9c3" />
<img width="1963" height="664" alt="image" src="https://github.com/user-attachments/assets/ddef8e67-6333-4367-b0bb-628717253510" />

By looking through the events, we can get both answers to the final two questions. The folder created was called 'History' and the word the rule looks for before deleting emails is 'Withdrawl'. Based on that information, it seems the attacker wanted to move any emails sent to Sabastian from Becky to the History folder. And, any emails from Sabastian to Becky that contain the word 'Withdrawl' get deleted. Pretty sneaky.
_________________________________________________________________________________________________________________

## Review/Learnings

This investigation lab focused on identifying means by which an attacker got access to and manipulated emails to allow them to make bank transactions while hiding their actions. The phishing email itself was just the start of the malicious activity and the means by which the attackers covered their tracks were crude, but effective at least for a normal user.

What I learned:
- Indicators for malicious links and how to verify if a link is good or bad
- How to narrow a search through Azure logs using PowerShell as a tool
- Keywords within Azure logs to help identify suspicious activity such as mailbox rules

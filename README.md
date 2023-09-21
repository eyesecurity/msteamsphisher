# Introduction
This GitHub repository contains information about he indicators of the Teams Phishing attack. Which we have used in our [blog](https://www.eye.security/blog/microsoft-teams-chat-the-rising-phishing-threat-and-how-to-stop-it). It will also contain updated information on how to remiadiate the attack.

# Indicators of Comprimise
The following list of indicators can be used to prepare your detection systems for a similar attack. Please note that these indicators will change over time, relatively quickly.

| Attribute type | Value | Description |
|----------------|-------|-------------|
| Hash | 237d1bca6e056df5bb16a1216a434634109478f882d3b1d58344c801d184f95d | AutoIt3.exe |
| Hash | 6aca36077144a2c44a86feba159c5557aae4129f32b9784e9c294bec462b5610 | Malicious au3 script
| Hash | 4037103e3da62794fba6a060bf654a536fe7d4eaf2d14bec69941f86f2bf54df | Malicious shortcut file |
| Hash | 11edca0a0529daddf1689e7c02dd4a0aa29c2bb29faad2a5b582a9664ab74b8e | Malicious shortcut file |
| Hash | 31fdcaa7f8fc8293b0b2c95098721dc61cbfab4ef863fa224dee81e30d964139 | Malicious shortcut file |
| Hash | c24ee7d0f3f68687d5390968ec23c9dd7bc68c61817d4c0f355a992591539e41 | Malicious shortcut file |
| Hash | 317063a3c83ac853e1dcb17d516445faf9798ad0150b3ac3f3f27f6830b3afb7 | Malicious shortcut file |
| IP | 5[.]188.87.58 | C2 server |
| Port | *:9999 | C2 Server Port |
| Port | *:2351 | C2 Server Port |
| User-Agent | User-Agent: Mozilla/4.0 (compatible; Synapse) | Malware User Agent |

Sample HTTP network traffic of DarkGate:

```
POST / HTTP/1.0
Host: 5[.]188.87.58:2351
Keep-Alive: 300 
Connection: keep-alive
User-Agent: Mozilla/4.0 (compatible; Synapse)
Content-Type: application/x-www-form-urlencoded
Content-Length: 221

id=REDACTED&data=REDACTED&act=1000

HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 2
Date: Tue, 12 Sep 2023 17:30:58 GMT

ok
```

# Hunting
Our sample of DarkGate left traces at the following locations:

1. `C:\Users\<username>\AppData\Local\Temp\Autoit3.exe`
2. `C:\Users\<username>\AppData\Local\Temp\<random>.au3`
3. `C:\users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\<random>.lnk`
4. `C:\ProgramData\<random>\<random>.au3`

# Queries for Incident Response
## Defender for Endpoint (KQL)
```
let Hashes = pack_array('237d1bca6e056df5bb16a1216a434634109478f882d3b1d58344c801d184f95d','6aca36077144a2c44a86feba159c5557aae4129f32b9784e9c294bec462b5610','317063a3c83ac853e1dcb17d516445faf9798ad0150b3ac3f3f27f6830b3afb7','4037103e3da62794fba6a060bf654a536fe7d4eaf2d14bec69941f86f2bf54df','11edca0a0529daddf1689e7c02dd4a0aa29c2bb29faad2a5b582a9664ab74b8e','3c470fc007a3c5d59f1c3c483510c60eeb07852905a58d01601bcd0bd2db1245','31fdcaa7f8fc8293b0b2c95098721dc61cbfab4ef863fa224dee81e30d964139','c24ee7d0f3f68687d5390968ec23c9dd7bc68c61817d4c0f355a992591539e41');
DeviceFileEvents
| where SHA256 in (Hashes)
```

```
DeviceNetworkEvents | where RemoteUrl contains "<domain used>-my.sharepoint.com"
```

## CrowdStrike (Splunk)

```
index=main event_simpleName=DnsRequest DomainName="<domain used>-my.sharepoint.com"
| dedup DomainName, ComputerName
| table DomainName, ComputerName
```
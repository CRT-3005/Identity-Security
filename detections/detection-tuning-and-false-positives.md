## Detection Tuning - Step 1

<img width="1862" height="814" alt="image" src="https://github.com/user-attachments/assets/3948f89e-fdeb-43fb-8452-95f7bd52cd13" />

**Baseline Authentication Activity – EventID 4624 / 4625**
Raw authentication baseline using Windows Security logs before any tuning or exclusions were applied.


<img width="1879" height="460" alt="image" src="https://github.com/user-attachments/assets/fbc1c4e0-a1ba-4366-8242-37f9b64c3c9c" />

**Successful Logon Types Baseline – EventID 4624**
Distribution of successful authentication logon types prior to any detection tuning.


## Detection Tuning – Step 2

```spl
index=identity sourcetype="WinEventLog:SecurityAll" "<EventID>4625</EventID>"
| rex field=_raw "TargetUserName.*?>(?<TargetUserName>[^<]+)<"
| rex field=_raw "Data Name='IpAddress'>(?<IpAddress>[^<]+)<"
| bin _time span=5m
| stats dc(TargetUserName) as unique_users values(TargetUserName) as users count as attempts by _time IpAddress
| where unique_users >= 3
| sort -attempts
```

<img width="1873" height="764" alt="image" src="https://github.com/user-attachments/assets/674bbcff-6d90-448c-aab7-11a5d489bf7c" />

**Untuned Password Spray Detection – Initial Results**
An untuned password spray detection was replayed against baseline authentication data. The detection surfaced repeated failed authentication attempts from a single internal IP address against multiple distinct user accounts within short time windows, consistent with password spraying behaviour.


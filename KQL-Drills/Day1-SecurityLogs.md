# KQL Daily Drills — Day 1
**Environment:** Azure Data Explorer — SecurityLogs database

## Drill 1 — Failed login count by username
```kql
AuthenticationEvents
| where result == "Failed Login"
| summarize FailedAttempts = count() by username
| order by FailedAttempts desc
```
**Finding:** jadenman had 22 failed attempts — top suspect for brute force

## Drill 2 — Failed logins by IP address
```kql
AuthenticationEvents
| where result == "Failed Login"
| summarize FailedAttempts = count() by src_ip
| order by FailedAttempts desc
```
**Finding:** 88.150.11.111 is external IP with 10 failed attempts — red flag

## Drill 3 — Phishing detection
```kql
Email
| where sender != reply_to
| project event_time, sender, reply_to, recipient, subject
```
**Finding:** 3,869 emails where reply_to differs from sender — possible phishing campaign

+++
title = "Volt Typhoon (Blue)"
date = "2026-08-17"
author = "berzrk"
description = "Investigate an instrusion by the APT Volt Typhoon"
+++

# Initial Access

When `Dean`'s password changed and their account take over by the attacker?

- Look for multiple failed `Access Unlock` attempts in sequence

```splunk-spl
index="main" sourcetype="adss" username=dean-admin
| table _time action_name ip_address status username
```

What is the name of new account created

- Change the time range to some minutes after the account was compromised and enrollment action name

```splunk-spl
index="main" sourcetype="adss"
| table _time action_name ip_address status username
```

# Execution

What command the attacker run to find information about local drives on server1 and 2

- Use **stack counting**

```splunk-spl
index="main" sourcetype="wmic"
| stats count by command
| sort count
```

Attacker uses `ntdsutil`. What password does the attacker set

```splunk-spl
index="main" sourcetype=* ntdsutil

# Then set 'since date time'
index="main" sourcetype="wmic"
| table _time command ip_address result username
```

# Persistence

Follow the next commands executed from the previous query

# Defense Evasion

While file name created by the attackers ?

- Continue following `wmic` logs timeline

What regedit path check for evidence of virtualized env?

```splunk-spl
index="main" sourcetype="powershell" HKEY
```

# Credential Access

What three pieces of software were used to find credentials with `reg query`

```splunk-spl
index="main" sourcetype="powershell" CommandLine="reg*"
```

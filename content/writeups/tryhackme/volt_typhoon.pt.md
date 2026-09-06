+++
title = "Volt Typhoon (Blue)"
date = "2026-08-17"
author = "berzrk"
description = "Investigação de uma intrusão do APT Volt Typhoon"
+++

# Initial Access

Quando a senha do `Dean` foi alterada e a conta dele tomada pelo atacante?

- Procure por várias tentativas de `Access Unlock` que falharam em sequência

```splunk-spl
index="main" sourcetype="adss" username=dean-admin
| table _time action_name ip_address status username
```

Qual é o nome da nova conta criada

- Mude o time range para alguns minutos depois de a conta ter sido comprometida e o action name de enrollment

```splunk-spl
index="main" sourcetype="adss"
| table _time action_name ip_address status username
```

# Execution

Qual comando o atacante executou para encontrar informações sobre os drives locais no server1 e no server2

- Use **stack counting**

```splunk-spl
index="main" sourcetype="wmic"
| stats count by command
| sort count
```

O atacante usa `ntdsutil`. Qual senha o atacante define

```splunk-spl
index="main" sourcetype=* ntdsutil

# Depois defina 'since date time'
index="main" sourcetype="wmic"
| table _time command ip_address result username
```

# Persistence

Siga os próximos comandos executados a partir da query anterior

# Defense Evasion

Qual nome de arquivo foi criado pelos atacantes?

- Continue seguindo a timeline dos logs do `wmic`

Qual caminho do regedit verifica evidências de ambiente virtualizado?

```splunk-spl
index="main" sourcetype="powershell" HKEY
```

# Credential Access

Quais três softwares foram usados para encontrar credenciais com `reg query`

```splunk-spl
index="main" sourcetype="powershell" CommandLine="reg*"
```

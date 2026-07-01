# CustomApp Log Generator (C#)

A small .NET 8 console tool that emits syslog-style `CustomApp` authentication
events into a log file the Wazuh agent watches. It exists to drive — and prove —
the custom decoder and correlation rules in `../detections/`.

## Build & run
Requires the .NET 8 SDK.
```bash
cd log-generator
dotnet run -- --scenario compromise --output /var/log/customapp.log
```
(On Windows the default output path is `C:\logs\customapp.log`.)

## Scenarios
| Scenario | What it produces | Rules exercised |
|---|---|---|
| `baseline` | Normal logins from varied users/IPs with ~10% noise failures | 100100/100101 |
| `bruteforce` | Many failures from one source IP | 100100 -> 100101 -> 100102 |
| `compromise` | A failure burst then a success from the same IP | 100102 -> 100103 |
| `mixed` | baseline, then bruteforce, then compromise | all |

## Options
```
--scenario <baseline|bruteforce|compromise|mixed>   default: bruteforce
--output <path>     log file to append to
--host <name>       hostname tag in each line        default: APPSRV
--srcip <ip>        attacker source IP               default: 10.10.10.20
--users <a,b,c>     user pool                        default: jdoe,asmith,svc_backup,mwilson
--count <n>         number of events                 default: 8
--delay <ms>        delay between events             default: 2000
--help
```

## Output format
```
MMM dd HH:mm:ss <HOST> CustomApp: action=<A> user=<U> srcip=<IP> reason=<R>
```
This format is matched exactly by `../detections/decoders/local_decoder.xml`. If
you change the line format, update the decoder regex to match.

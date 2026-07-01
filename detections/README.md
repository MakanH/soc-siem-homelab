# Custom Detections

Hand-written Wazuh decoders and correlation rules for this lab. These are the
engineering artifacts behind the "custom XML decoders and correlation rules"
work — not stock Wazuh content.

## Files
- `decoders/local_decoder.xml` — parses the `CustomApp` log into named fields
- `rules/local_rules.xml` — the detection/correlation ladder built on those fields

## Rule catalog
| Rule ID | Level | Fires when | MITRE | Source |
|---|---|---|---|---|
| 100100 | 3 | Any CustomApp event is decoded | — | CustomApp log |
| 100101 | 5 | A single `LOGIN_FAILED` | T1110 | CustomApp log |
| 100102 | 10 | 5+ failures from the same `srcip` within 120s (brute force) | T1110 | correlation |
| 100103 | 12 | A `LOGIN_SUCCESS` from that `srcip` within 300s (compromise) | T1110 | correlation |

## Deploy
On the Wazuh manager:
```bash
sudo cp decoders/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml
sudo cp rules/local_rules.xml      /var/ossec/etc/rules/local_rules.xml
```

## Test before reloading
```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a sample line, e.g.:
# Jun 07 14:03:11 APPSRV CustomApp: action=LOGIN_FAILED user=jdoe srcip=10.10.10.20 reason=bad_password
```
`wazuh-logtest` should show the line decoded into `action/user/srcip/reason` and
matching rule `100101`. Then reload:
```bash
sudo systemctl restart wazuh-manager
```

## Generate the events
Use the C# tool in `../log-generator/` to drive these rules end to end:
```bash
dotnet run -- --scenario compromise --output /var/log/customapp.log
```
Watch the alerts climb level 5 -> 10 -> 12 in the dashboard's Security Events.

# SID registry

Range **9100001–9199999** is reserved for LogManthan OT rules. A SID is never reused,
even after a rule is retired: mark it *retired* here instead of deleting the row.

Priority: `1` = Critical (opens a case), `2` = Medium (alert only), `3` = Low.

The MITRE column is written into each rule as `metadata:mitre_technique_id Txxxx` (one key per
technique), the field LogManthan reads. The older `mitre_ics` key is rejected by the lint.

| SID | msg | priority | MITRE ATT&CK for ICS | test fixture |
|---|---|---|---|---|
| 9100001 | LM-OT Modbus write from unauthorised host | 1 | T0855, T0836 | `bro_modbus_modbus`, `lab_write`, `lab_modbus_long_session_depth_10mb` |
| 9100002 | LM-OT Modbus diagnostics Force Listen Only Mode (device goes silent) | 1 | T0814 | `bro_modbus_modbus`, `lab_listen_only` |
| 9100003 | LM-OT Modbus diagnostics Restart Communications | 1 | T0816 | `bro_modbus_modbus`, `lab_restart_comms` |
| 9100004 | LM-OT Modbus Read Device Identification (fingerprinting) | 2 | T0846 | `bro_modbus_modbus`, `lab_scan` |
| 9100005 | LM-OT Modbus user-defined or reserved function code | 2 | T0855 | **none yet** |
| 9100006 | LM-OT Modbus scan - many connections from one host | 2 | T0846 | `lab_scan` |
| 9100007 | LM-OT Modbus request flood from unknown host (rev 2: was any host) | 2 | T0814 | `lab_flood`, `lab_flood_heavy` |
| 9100008 | LM-OT Modbus request flood from any host (incl. allowed writers) (rev 2: 2000 in 10 s, was 1000) | 2 | T0814 | `lab_flood_heavy`, `lab_flood_heavy_allowed_writer` |
| 9100010 | LM-OT DNP3 Cold Restart command | 1 | T0816 | `dnp3_cold_restart_and_response`, `lab_dnp3_cold_restart`, `lab_dnp3_long_session_depth_10mb` |
| 9100011 | LM-OT DNP3 Warm Restart command | 1 | T0816 | `dnp3_warm_restart_and_response`, `lab_dnp3_warm_restart` |
| 9100012 | LM-OT DNP3 Direct Operate from non-master | 1 | T0855 | `dnp3_directoperate_and_response`, `dnp3_direct_operate_analog_output`, `lab_dnp3_direct_operate` |
| 9100013 | LM-OT DNP3 Write from non-master | 1 | T0836 | `dnp3_write_binary_output`, `lab_dnp3_write` |
| 9100014 | LM-OT DNP3 Select (control) from non-master | 1 | T0855 | `dnp3_select_operate_and_responses` |
| 9100015 | LM-OT DNP3 Operate from non-master | 1 | T0855 | `dnp3_select_operate_and_responses` |
| 9100016 | LM-OT DNP3 Disable Unsolicited Responses (operator loses alarms) | 1 | T0878 | `dnp3_disable_unsolcited_and_response`, `lab_dnp3_disable_unsolicited` |
| 9100017 | LM-OT DNP3 Delete File on outstation | 1 | T0809 | `dnp3_file_delete` |
| 9100020 | LM-OT ENIP List Identity discovery from non-engineering host | 2 | T0846 | `EthernetIP_enip_test` |
| 9100030 | LM-OT S7comm PLC STOP request | 1 | T0858, T0816 | **none yet** |
| 9100040 | LM-OT Remote service connection from IT into OT | 1 | T0886 | **none yet** |

Should-not-fire (silent) fixtures:
- `dnp3_read_and_response`: normal DNP3 read; no LM SID may fire.
- `lab_hmi_normal`: normal HMI polling plus allowed writes; no LM SID may fire (covers 9100001, 9100007 and 9100008).
- `lab_dnp3_master_normal`: 10 minutes of normal DNP3 master polling plus its allowed WRITE; no LM SID may fire
  (covers 9100013 for masters) and no Suricata DNP3 event.
- `iti_modbustcp_master_allowed` (`absent`): ITI ModbusTCP, a real master polling at ~62 requests/s
  (peak 663 in 10 s), with every non-test host in `OT_WRITERS`; neither 9100007 nor 9100008 may fire.

`lab_*` fixtures are our own lab captures in `tests/suricata/lab/` and use `exact` matching:
the expected SIDs must fire and no other LM SID may. `lab_flood_heavy_allowed_writer` replays the
heavy flood with the attacker added to `OT_WRITERS` (a compromised allowed host): only 9100008 fires.

Known blind spot, tested (`absent`): `lab_modbus_long_session` and `lab_dnp3_long_session` send the
write / Cold Restart after 1.1 MiB on one connection. At Suricata's default `stream.reassembly.depth`
(1 MiB) 9100001 and 9100010 must **not** fire; their `_depth_10mb` twins replay the same capture with
`stream.reassembly.depth=10mb` and must fire (exact). See README "Stream reassembly depth".

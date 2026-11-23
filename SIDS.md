# SID registry

Range **9100001–9199999** is reserved for LogManthan OT rules. A SID is never reused,
even after a rule is retired: mark it *retired* here instead of deleting the row.

Priority: `1` = Critical (opens a case), `2` = Medium (alert only), `3` = Low.

| SID | msg | priority | MITRE ATT&CK for ICS | test fixture |
|---|---|---|---|---|
| 9100001 | LM-OT Modbus write from unauthorised host | 1 | T0855, T0836 | `bro_modbus_modbus`, `lab_write` |
| 9100002 | LM-OT Modbus diagnostics Force Listen Only Mode (device goes silent) | 1 | T0814 | `bro_modbus_modbus`, `lab_listen_only` |
| 9100003 | LM-OT Modbus diagnostics Restart Communications | 1 | T0816 | `bro_modbus_modbus`, `lab_restart_comms` |
| 9100004 | LM-OT Modbus Read Device Identification (fingerprinting) | 2 | T0846 | `bro_modbus_modbus`, `lab_scan` |
| 9100005 | LM-OT Modbus user-defined or reserved function code | 2 | T0855 | **none yet** |
| 9100006 | LM-OT Modbus scan - many connections from one host | 2 | T0846 | `lab_scan` |
| 9100007 | LM-OT Modbus request flood from unknown host (rev 2: was any host) | 2 | T0814 | `lab_flood`, `lab_flood_heavy` |
| 9100008 | LM-OT Modbus request flood from any host (incl. allowed writers) | 2 | T0814 | `lab_flood_heavy`, `lab_flood_heavy_allowed_writer` |
| 9100010 | LM-OT DNP3 Cold Restart command | 1 | T0816 | `dnp3_cold_restart_and_response` |
| 9100011 | LM-OT DNP3 Warm Restart command | 1 | T0816 | `dnp3_warm_restart_and_response` |
| 9100012 | LM-OT DNP3 Direct Operate from non-master | 1 | T0855 | `dnp3_directoperate_and_response`, `dnp3_direct_operate_analog_output` |
| 9100013 | LM-OT DNP3 Write from non-master | 1 | T0836 | `dnp3_write_binary_output` |
| 9100014 | LM-OT DNP3 Select (control) from non-master | 1 | T0855 | `dnp3_select_operate_and_responses` |
| 9100015 | LM-OT DNP3 Operate from non-master | 1 | T0855 | `dnp3_select_operate_and_responses` |
| 9100016 | LM-OT DNP3 Disable Unsolicited Responses (operator loses alarms) | 1 | T0878 | `dnp3_disable_unsolcited_and_response` |
| 9100017 | LM-OT DNP3 Delete File on outstation | 1 | T0809 | `dnp3_file_delete` |
| 9100020 | LM-OT ENIP List Identity discovery from non-engineering host | 2 | T0846 | `EthernetIP_enip_test` |
| 9100030 | LM-OT S7comm PLC STOP request | 1 | T0858, T0816 | **none yet** |
| 9100040 | LM-OT Remote service connection from IT into OT | 1 | T0886 | **none yet** |

Should-not-fire (silent) fixtures:
- `dnp3_read_and_response`: normal DNP3 read; no LM SID may fire.
- `lab_hmi_normal`: normal HMI polling plus allowed writes; no LM SID may fire (covers 9100001, 9100007 and 9100008).
- `iti_modbustcp_master_allowed` (`absent`): ITI ModbusTCP, a real master polling at ~62 requests/s
  (peak 663 in 10 s), with every non-test host in `OT_WRITERS`; neither 9100007 nor 9100008 may fire.

`lab_*` fixtures are our own lab captures in `tests/suricata/lab/` and use `exact` matching:
the expected SIDs must fire and no other LM SID may. `lab_flood_heavy_allowed_writer` replays the
heavy flood with the attacker added to `OT_WRITERS` (a compromised allowed host): only 9100008 fires.

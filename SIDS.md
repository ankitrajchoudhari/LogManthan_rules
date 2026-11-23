# SID registry

Range **9100001–9199999** is reserved for LogManthan OT rules. A SID is never reused,
even after a rule is retired: mark it *retired* here instead of deleting the row.

Priority: `1` = Critical (opens a case), `2` = Medium (alert only), `3` = Low.

| SID | msg | priority | MITRE ATT&CK for ICS | test fixture |
|---|---|---|---|---|
| 9100001 | LM-OT Modbus write from unauthorised host | 1 | T0855, T0836 | `bro_modbus_modbus` |
| 9100002 | LM-OT Modbus diagnostics Force Listen Only Mode (device goes silent) | 1 | T0814 | `bro_modbus_modbus` |
| 9100003 | LM-OT Modbus diagnostics Restart Communications | 1 | T0816 | `bro_modbus_modbus` |
| 9100004 | LM-OT Modbus Read Device Identification (fingerprinting) | 2 | T0846 | `bro_modbus_modbus` |
| 9100005 | LM-OT Modbus user-defined or reserved function code | 2 | T0855 | **none yet** |
| 9100006 | LM-OT Modbus scan - many connections from one host | 2 | T0846 | **none yet** (lab `scan`, phase 2/3) |
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

Should-not-fire (silent) fixture: `dnp3_read_and_response` (normal DNP3 read, no LM SID may fire).

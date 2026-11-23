# Attribution

## Test captures

**ITI ICS-Security-Tools: pcaps**
- Source: https://github.com/ITI/ICS-Security-Tools (`pcaps/` folder)
- Licence: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- Found via: https://github.com/SackOfHacks/ICS-PCAP-Challenges
- Used: 11 DNP3, EtherNet/IP and Modbus captures listed in `tests/suricata/fixtures.json`.
- **Not stored in this repo.** `scripts/test_suricata.py` downloads each file into `.cache/`
  at test time and refuses it if its SHA-256 differs from the one pinned in `fixtures.json`.
- No changes made: the captures are replayed as published.

## Licence text
- `LICENSE`: Detection Rule License 1.1, from https://github.com/SigmaHQ/Detection-Rule-License

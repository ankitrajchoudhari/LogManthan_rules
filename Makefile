# LogManthan_rules: tests and OT lab.
COMPOSE        := docker compose -f lab/docker-compose.yml
SURICATA_IMAGE := jasonish/suricata@sha256:bf4bea5b45d9c10265a3ee6628e2ec8930b9d1fb7caf9d1afb63af413b9cbb26
SCENARIO ?= write
NAME     ?= capture
DURATION ?= 30
ARGS     ?=
HOST     ?=
# Python 3.11+ for the Sigma tests (on Windows: make sigma-setup PYTHON=python).
PYTHON   ?= python3
# The venv's interpreter once `make sigma-setup` has created it (Linux or Windows layout).
VENV_PY   = $(firstword $(wildcard .venv/bin/python .venv/Scripts/python.exe) $(PYTHON))

# Git Bash on Windows rewrites container paths like /src; this turns that off (no effect elsewhere).
export MSYS_NO_PATHCONV := 1

.PHONY: help test lab-up lab-down lab-logs attack alerts capture record-fixtures sigma-setup sigma-deps sigma-test sigma-events

help:
	@echo "make test                         lint + suricata -T + pcap replay (Suricata 8.0.7 container)"
	@echo "make sigma-setup [PYTHON=python]  create .venv with the hash-pinned Sigma tools (sigma/requirements.txt)"
	@echo "make sigma-test                   sigma check + field/SID sync + correlation scenarios"
	@echo "make sigma-events [CHECK=1]       rebuild (or check) tests/sigma/events from the lab captures"
	@echo "make lab-up                       build and start PLC, HMI and Suricata sensor"
	@echo "make attack SCENARIO=<name>       scan | write | listen-only | restart-comms | flood"
	@echo "make alerts [ARGS=...]            show LM-OT alerts from lab/out/eve.json"
	@echo "make capture NAME=x DURATION=30 [HOST=ip]  record lab traffic to lab/out/x.pcap"
	@echo "make record-fixtures             re-record tests/suricata/lab/*.pcap from the running lab"
	@echo "make lab-logs / make lab-down"

test:
	docker run --rm -v "$(CURDIR):/src" -w /src --entrypoint python3 $(SURICATA_IMAGE) scripts/test_suricata.py

sigma-setup:
	$(PYTHON) -m venv .venv
	$(MAKE) --no-print-directory sigma-deps

sigma-deps:
	$(VENV_PY) -m pip install --require-hashes -r sigma/requirements.txt

sigma-test:
	$(VENV_PY) scripts/test_sigma.py

sigma-events:
	docker run --rm -v "$(CURDIR):/src" -w /src --entrypoint python3 $(SURICATA_IMAGE) scripts/build_sigma_events.py $(if $(CHECK),--check)

lab-up:
	$(COMPOSE) up -d --build

lab-down:
	$(COMPOSE) --profile attack --profile capture down --remove-orphans

lab-logs:
	$(COMPOSE) logs --tail 50

attack:
	$(COMPOSE) run --rm attacker $(SCENARIO)

alerts:
	docker run --rm -v "$(CURDIR)/lab:/lab:ro" --entrypoint python3 $(SURICATA_IMAGE) /lab/tools/alerts.py /lab/out/eve.json $(ARGS)

capture:
	$(COMPOSE) run --rm capture $(NAME) $(DURATION) $(HOST)

record-fixtures:
	sh lab/tools/record_fixtures.sh

# Solar Farm OT Security Watchman — Makefile
# Compatible with GNU Make on Linux, macOS, and WSL2.
# On Windows (without WSL2), use the equivalent PowerShell scripts in scripts/.

.PHONY: doctor build up down status logs reset baseline demo scenario evaluate test clean help

COMPOSE = docker compose
API_URL = http://127.0.0.1:8000
DASHBOARD_URL = http://127.0.0.1:8501
HMI_URL = http://127.0.0.1:1881
FUXA_URL = http://127.0.0.1:1881

# Default target
help:
	@echo ""
	@echo "  Solar Farm OT Security Watchman"
	@echo "  ================================"
	@echo ""
	@echo "  make doctor       Check prerequisites (Docker, ports, config, capture)"
	@echo "  make build        Build all Docker images"
	@echo "  make up           Start the lab"
	@echo "  make status       Show service health and packet visibility"
	@echo "  make logs         Follow service logs"
	@echo "  make test         Run unit + integration tests (local-only, safe)"
	@echo "  make baseline     Generate normal-traffic baseline and train ML model"
	@echo "  make demo         Run the complete bounded attack demo (all scenarios)"
	@echo "  make scenario S=S1  Run one named scenario (S1–S5)"
	@echo "  make evaluate     Run labelled trials and compute B.2 acceptance metrics"
	@echo "  make reset        Reset generated lab data, restore clean state"
	@echo "  make down         Stop the lab"
	@echo ""
	@echo "  URLs (after 'make up'):"
	@echo "    Dashboard:  $(DASHBOARD_URL)"
	@echo "    FUXA HMI:   $(HMI_URL)"
	@echo "    API docs:   $(API_URL)/docs"
	@echo ""

doctor:
	@echo "── Running preflight checks ────────────────────────────────"
	python3 scripts/doctor.py

build:
	@echo "── Building Docker images ──────────────────────────────────"
	$(COMPOSE) build

up:
	@echo "── Starting the solar farm lab ─────────────────────────────"
	$(COMPOSE) up -d
	@echo ""
	@echo "  Waiting for services to start..."
	@sleep 10
	@$(MAKE) status
	@echo ""
	@echo "  Dashboard:  $(DASHBOARD_URL)"
	@echo "  FUXA HMI:   $(HMI_URL)"
	@echo "  API docs:   $(API_URL)/docs"

down:
	@echo "── Stopping the lab ────────────────────────────────────────"
	$(COMPOSE) down

status:
	@echo "── Service Health ──────────────────────────────────────────"
	$(COMPOSE) ps
	@echo ""
	@echo "── API Health ──────────────────────────────────────────────"
	@curl -sf $(API_URL)/health 2>/dev/null | python3 -m json.tool || echo "  API not reachable"
	@echo ""
	@echo "── Sensor Health ───────────────────────────────────────────"
	@curl -sf $(API_URL)/sensor/health 2>/dev/null | python3 -m json.tool || echo "  Sensor health not available"

logs:
	$(COMPOSE) logs -f --tail=50

test:
	@echo "── Running unit + integration tests ────────────────────────"
	python3 -m pytest tests/ -v --tb=short 2>&1 | head -100

baseline:
	@echo "── Generating normal-traffic baseline ──────────────────────"
	@echo "  Posting synthetic baseline to API..."
	python3 scripts/generate_baseline.py --synthetic
	@echo ""
	@echo "  ✅ Baseline generated. ML model is now trained."
	@echo "     Run 'make demo' to start attack scenarios."

demo:
	@echo "── Running full attack scenario demo ───────────────────────"
	@echo "  ⚠️  All attacks target ONLY local lab containers."
	@echo "  ⚠️  No real OT systems, networks, or PLCs are affected."
	@echo ""
	python3 scripts/run_scenario.py all --trial 1
	@echo ""
	@echo "  ✅ Demo complete. View alerts at: $(DASHBOARD_URL)"

scenario:
	@if [ -z "$(S)" ]; then \
		echo "Usage: make scenario S=S1"; \
		echo "Available: S1 S2 S3 S4 S5"; \
		exit 1; \
	fi
	@echo "── Running scenario $(S) ────────────────────────────────────"
	python3 scripts/run_scenario.py $(S)

evaluate:
	@echo "── Running B.2 evaluation trials & metrics ──────────────────"
	python3 scripts/evaluate.py --run-trials

reset:
	@echo "── Resetting lab data ──────────────────────────────────────"
	@echo "  Stopping services..."
	$(COMPOSE) down
	@echo "  Removing SQLite database..."
	@docker volume rm cognton_db_data 2>/dev/null || true
	@echo "  Removing Zeek logs..."
	@docker volume rm cognton_zeek_logs 2>/dev/null || true
	@echo "  Removing PCAP data..."
	@docker volume rm cognton_pcap_data 2>/dev/null || true
	@echo "  ✅ Lab data reset. Run 'make up' to restart."
	@echo "  📁 Source files are unchanged."

clean: reset
	$(COMPOSE) down --rmi local --volumes

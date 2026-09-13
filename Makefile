# Sentinel Platform - centralized logging and security monitoring
#
# Local stack:   make up && make bootstrap && make demo
# Kubernetes:    make k8s-deploy
# Tests:         make test

SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE      ?= docker compose
ES_URL       ?= http://localhost:9200
KB_URL       ?= http://localhost:5601
APP_URL      ?= http://localhost:8080
NAMESPACE    ?= observability

export ELASTIC_PASSWORD ?= changeme-local-only
export KIBANA_PASSWORD  ?= changeme-local-only

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- Local stack ------------------------------------------------------------

.PHONY: up
up: ## Start the full local stack (Elasticsearch, Logstash, Kibana, app, nginx, Filebeat)
	$(COMPOSE) up -d --build
	@echo
	@echo "Waiting for Kibana to become available (first boot runs migrations)..."
	@for i in $$(seq 1 60); do \
	  if curl -sf $(KB_URL)/api/status 2>/dev/null | grep -q '"level":"available"'; then \
	    echo "  Kibana is up."; break; \
	  fi; \
	  printf '.'; sleep 5; \
	done
	@echo
	@echo "  Kibana:        $(KB_URL)   (elastic / $$ELASTIC_PASSWORD)"
	@echo "  Elasticsearch: $(ES_URL)"
	@echo "  Application:   $(APP_URL)"
	@echo
	@echo "Next:  make bootstrap"

.PHONY: down
down: ## Stop the stack, keeping data volumes
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and DELETE all indexed data
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail logs from every service
	$(COMPOSE) logs -f --tail=50

.PHONY: ps
ps: ## Show service status
	$(COMPOSE) ps

# --- Platform setup ---------------------------------------------------------

.PHONY: bootstrap
bootstrap: ## Install ILM policies, index templates and detection rules
	ELASTICSEARCH_URL=$(ES_URL) ./scripts/bootstrap-elasticsearch.sh
	@echo
	KIBANA_URL=$(KB_URL) ./scripts/install-detections.sh
	@echo
	KIBANA_URL=$(KB_URL) ./scripts/import-dashboards.sh

# --- Demo -------------------------------------------------------------------

.PHONY: demo
demo: ## Run every attack scenario, then 5 minutes of baseline traffic
	@echo "Running attack scenarios..."
	python3 scripts/traffic_generator.py --target $(APP_URL) --scenario all
	@echo
	@echo "Generating baseline traffic for 5 minutes..."
	python3 scripts/traffic_generator.py --target $(APP_URL) --duration 300 --rps 8

.PHONY: traffic
traffic: ## Baseline traffic only (override: make traffic DURATION=600 RPS=20)
	python3 scripts/traffic_generator.py --target $(APP_URL) \
	  --duration $(or $(DURATION),300) --rps $(or $(RPS),8)

.PHONY: attack
attack: ## Run one scenario (make attack SCENARIO=brute_force)
	@test -n "$(SCENARIO)" || { echo "usage: make attack SCENARIO=<name>"; \
	  echo "available: brute_force password_spray web_attack enumeration data_exfil privilege_escalation error_spike"; exit 1; }
	python3 scripts/traffic_generator.py --target $(APP_URL) --scenario $(SCENARIO)

# --- Blockchain testnet -----------------------------------------------------

CHAIN_RPC ?= http://localhost:8545

.PHONY: chain-up
chain-up: ## Start a local 3-node testnet (no Docker needed)
	./scripts/run-local-testnet.sh

.PHONY: chain-status
chain-status: ## Show chain head, peers, validators and any slashing evidence
	@curl -s $(CHAIN_RPC)/status | python3 -c "import sys,json; \
s=json.load(sys.stdin); \
print(f\"node={s['node_id']} height={s['height']} slot={s['slot']} epoch={s['epoch']}\"); \
print(f\"peers={len(s['peers'])} mempool={s['mempool']} finalized={s['finalized_height']}\"); \
print(f\"rpc namespaces: {','.join(s['enabled_namespaces'])}\"); \
o=s['slashable_offences']; \
print(f\"slashable offences: {len(o)}\"); \
[print(f\"   {x['kind']} validator={x['validator_index']} slot={x['slot']}\") for x in o[:5]]" \
	  2>/dev/null || echo "chain not reachable at $(CHAIN_RPC)"

.PHONY: chain-attack
chain-attack: ## Run one blockchain scenario (make chain-attack SCENARIO=double_sign)
	@test -n "$(SCENARIO)" || { echo "usage: make chain-attack SCENARIO=<name>"; \
	  python3 scripts/blockchain_attacks.py --list; exit 1; }
	python3 scripts/blockchain_attacks.py --target $(CHAIN_RPC) --scenario $(SCENARIO)

.PHONY: chain-demo
chain-demo: ## Run every blockchain attack scenario against the testnet
	python3 scripts/blockchain_attacks.py --target $(CHAIN_RPC) --scenario all

.PHONY: chain-scenarios
chain-scenarios: ## List the available blockchain attack scenarios
	@python3 scripts/blockchain_attacks.py --list

.PHONY: chain-verify
chain-verify: ## Evaluate all detection rules against the captured testnet logs
	@test -f testnet-logs/node-0.log || { echo "no capture found - run 'make chain-up' first"; exit 1; }
	python3 tests/simulate_detections.py testnet-logs/node-0.log

# --- Tests ------------------------------------------------------------------

.PHONY: test
test: test-crypto test-consistency test-pipeline ## Run all offline tests

.PHONY: test-crypto
test-crypto: ## Verify the secp256k1 implementation against published vectors
	python3 tests/test_crypto.py

.PHONY: test-consistency
test-consistency: ## Validate rules, mappings and templates agree (no cluster needed)
	python3 tests/test_platform_consistency.py

.PHONY: test-pipeline
test-pipeline: ## Verify the Logstash config parses
	@if $(COMPOSE) ps logstash 2>/dev/null | grep -q Up; then \
	  $(COMPOSE) exec -T logstash \
	    logstash --config.test_and_exit \
	             --path.settings /usr/share/logstash/config \
	             -f '/usr/share/logstash/pipeline/*.conf'; \
	else \
	  echo "Logstash is not running - start it with 'make up' to test the pipeline config."; \
	fi

.PHONY: test-detections
test-detections: ## Replay a captured log through the rules (make test-detections LOG=path)
	@test -n "$(LOG)" || { echo "usage: make test-detections LOG=<app.jsonl>"; exit 1; }
	python3 tests/simulate_detections.py $(LOG)

# --- Kubernetes -------------------------------------------------------------

.PHONY: k8s-secrets
k8s-secrets: ## Create the namespace secrets (run once before k8s-deploy)
	kubectl create namespace $(NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(NAMESPACE) create secret generic elastic-credentials \
	  --from-literal=password="$$ELASTIC_PASSWORD" \
	  --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n $(NAMESPACE) create secret generic kibana-credentials \
	  --from-literal=password="$$KIBANA_PASSWORD" \
	  --from-literal=encryptionKey="$$(openssl rand -hex 32)" \
	  --dry-run=client -o yaml | kubectl apply -f -
	@echo
	@echo "TLS certificates are not generated here. Create the"
	@echo "'elasticsearch-certs' secret with tls.crt, tls.key and ca.crt"
	@echo "using cert-manager or elasticsearch-certutil - see docs/architecture.md."

.PHONY: k8s-deploy
k8s-deploy: ## Deploy to Kubernetes with kustomize
	kubectl apply -k k8s/
	@echo
	kubectl -n $(NAMESPACE) rollout status statefulset/elasticsearch --timeout=5m
	kubectl -n $(NAMESPACE) rollout status deployment/logstash --timeout=3m
	kubectl -n $(NAMESPACE) rollout status deployment/kibana --timeout=5m

.PHONY: k8s-status
k8s-status: ## Show the state of everything in the namespace
	@kubectl -n $(NAMESPACE) get pods,svc,pvc -o wide
	@echo
	@kubectl -n $(NAMESPACE) get daemonset elastic-agent 2>/dev/null || true

.PHONY: k8s-forward
k8s-forward: ## Port-forward Kibana to localhost:5601
	kubectl -n $(NAMESPACE) port-forward svc/kibana 5601:5601

.PHONY: k8s-delete
k8s-delete: ## Remove everything from the cluster
	kubectl delete -k k8s/ --ignore-not-found

# --- Diagnostics ------------------------------------------------------------

.PHONY: health
health: ## Show cluster health, ingest rates and index sizes
	@echo "=== Cluster health ==="
	@curl -s -u elastic:$$ELASTIC_PASSWORD "$(ES_URL)/_cluster/health?pretty" \
	  | grep -E '"(status|number_of_nodes|active_shards|unassigned_shards)"' || true
	@echo
	@echo "=== Data streams ==="
	@curl -s -u elastic:$$ELASTIC_PASSWORD "$(ES_URL)/_cat/indices/.ds-logs-*?v&h=index,docs.count,store.size&s=index" || true
	@echo
	@echo "=== Logstash pipeline ==="
	@curl -s "http://localhost:9600/_node/stats/pipelines/main" \
	  | python3 -c "import sys,json; d=json.load(sys.stdin)['pipelines']['main']; e=d['events']; \
print(f\"  in={e['in']} out={e['out']} filtered={e['filtered']} queue_push_duration={e.get('queue_push_duration_in_millis',0)}ms\")" 2>/dev/null \
	  || echo "  Logstash API not reachable"

.PHONY: alerts
alerts: ## Show detection rules and whether they have fired
	@curl -s -u elastic:$$ELASTIC_PASSWORD \
	  "$(KB_URL)/api/detection_engine/rules/_find?per_page=50" -H 'kbn-xsrf: true' \
	  | python3 -c "import sys,json; \
rs=json.load(sys.stdin).get('data',[]); \
print(f'{len(rs)} rules installed\n'); \
[print(f\"  {r['rule_id']:9} {r['name'][:46]:46} enabled={r['enabled']}\") for r in sorted(rs,key=lambda x:x.get('rule_id',''))]" \
	  2>/dev/null || echo "Kibana not reachable"

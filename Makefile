# =============================================================================
# Makefile — Common development commands
# Usage: make <target>
# =============================================================================

.DEFAULT_GOAL := help
.PHONY: help lint fmt security test clean

# ─── Variables ────────────────────────────────────────────────────────────────
ENV ?= dev
TFSEC_VERSION ?= v1.28.4
CHECKOV_VERSION ?= 3.2.0

# ─── Help ─────────────────────────────────────────────────────────────────────
help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Format & Validate ────────────────────────────────────────────────────────
fmt: ## Format all Terraform files
	terraform fmt -recursive .

fmt-check: ## Check Terraform formatting (CI mode)
	terraform fmt -recursive -check -diff .

validate: ## Validate all modules
	@for dir in modules/*/; do \
		echo "Validating $$dir..."; \
		(cd $$dir && terraform init -backend=false -quiet && terraform validate); \
	done
	@echo "✅ All modules validated"

# ─── Security Scanning ────────────────────────────────────────────────────────
tfsec: ## Run tfsec security scan
	tfsec . --minimum-severity HIGH --config-file .tfsec.yml

checkov: ## Run checkov policy scan
	checkov -d . --framework terraform --compact \
		--output cli \
		--download-external-modules false

opa: ## Evaluate OPA policies against dev plan
	@echo "Generating terraform plan for OPA evaluation..."
	cd environments/$(ENV) && \
		terraform plan -var-file="terraform.tfvars" -out=tfplan.binary -no-color 2>/dev/null && \
		terraform show -json tfplan.binary > tfplan.json
	opa eval \
		--input environments/$(ENV)/tfplan.json \
		--data policies/opa/tagging.rego \
		--data policies/opa/encryption.rego \
		--data policies/opa/networking.rego \
		--format pretty \
		"data.enterprise.terraform.deny"

security: tfsec checkov ## Run all security scans

# ─── Testing ──────────────────────────────────────────────────────────────────
test: ## Run Terratest unit tests (fast, no AWS resources)
	cd tests && go test -v -short -timeout 10m ./...

test-integration: ## Run full Terratest integration tests (deploys real AWS resources)
	cd tests && go test -v -timeout 90m ./...

test-vpc: ## Run VPC module tests only
	cd tests && go test -v -run TestVPCModule -timeout 30m

test-s3: ## Run S3 module tests only
	cd tests && go test -v -run TestS3Module -timeout 15m

test-tags: ## Run tagging enforcement tests
	cd tests && go test -v -run TestTaggingEnforcement -timeout 10m

# ─── Development ──────────────────────────────────────────────────────────────
plan: ## Run terraform plan for environment (ENV=dev|staging|prod)
	cd environments/$(ENV) && terraform plan -var-file="terraform.tfvars" -no-color

drift: ## Run drift detection for environment
	./scripts/drift-detection.sh --env $(ENV) --alert-on-drift false

lint: fmt-check validate ## Run all linting checks

# ─── Pre-commit ───────────────────────────────────────────────────────────────
pre-commit: lint security ## Run all checks before committing
	@echo ""
	@echo "✅ All pre-commit checks passed. Safe to commit."

# ─── Cleanup ──────────────────────────────────────────────────────────────────
clean: ## Remove generated files
	find . -name "tfplan.binary" -delete
	find . -name "tfplan.json" -delete
	find . -name ".terraform" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf reports/
	@echo "✅ Cleaned up generated files"
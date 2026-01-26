.PHONY: coverage coverage-check e2e

CARGO_TARGET_DIR ?= target

coverage:
	cargo llvm-cov --workspace --html
	@echo "Coverage report: $(CARGO_TARGET_DIR)/llvm-cov/html/index.html"

coverage-check:
	cargo llvm-cov --workspace --fail-under-lines 80

e2e:
	./scripts/e2e_test.sh

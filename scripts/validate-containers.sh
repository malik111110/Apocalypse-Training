#!/usr/bin/env bash
# validate-containers.sh
# Validate Podman builds and compose configuration for the Apocalypse platform.
# Usage: ./scripts/validate-containers.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

fail=0

# ─── Check prerequisites ───
log_info "Checking prerequisites..."

if ! command -v podman &>/dev/null; then
    log_error "podman is not installed"
    fail=1
else
    log_info "podman: $(podman --version)"
fi

if ! command -v podman-compose &>/dev/null; then
    log_warn "podman-compose is not installed (optional for validation)"
fi

# ─── Validate Containerfile syntax ───
log_info "Validating Containerfiles..."

for ctx in "Apocalypse-chat-core" "Apocalypse-chat-UI" "apocalypse-cli"; do
    cf="${WORKSPACE_ROOT}/${ctx}/Containerfile"
    if [[ -f "$cf" ]]; then
        log_info "  Found: ${ctx}/Containerfile"
        # Basic syntax validation: check for required directives
        if ! grep -q '^FROM' "$cf"; then
            log_error "  ${ctx}/Containerfile missing FROM directive"
            fail=1
        fi
        if ! grep -q '^EXPOSE' "$cf"; then
            log_warn "  ${ctx}/Containerfile missing EXPOSE directive"
        fi
        if ! grep -q 'USER' "$cf"; then
            log_error "  ${ctx}/Containerfile missing USER directive (rootless required)"
            fail=1
        fi
    else
        log_error "Missing: ${ctx}/Containerfile"
        fail=1
    fi
done

# ─── Validate compose.yml syntax ───
log_info "Validating compose.yml..."
compose="${WORKSPACE_ROOT}/compose.yml"
if [[ -f "$compose" ]]; then
    # Check for required services
    for svc in postgres redis apocalypse-core apocalypse-ui; do
        if grep -q "^  ${svc}:" "$compose"; then
            log_info "  Service defined: ${svc}"
        else
            log_error "  Service missing: ${svc}"
            fail=1
        fi
    done

    # Check security settings
    if grep -q 'no-new-privileges:true' "$compose"; then
        log_info "  Security: no-new-privileges enabled"
    else
        log_warn "  Security: no-new-privileges not found"
    fi

    if grep -q 'read_only:' "$compose"; then
        log_info "  Security: read_only root fs enabled on some services"
    fi

    if grep -q 'cap_drop:' "$compose"; then
        log_info "  Security: capabilities dropped"
    fi
else
    log_error "Missing: compose.yml"
    fail=1
fi

# ─── Validate .env.example exists ───
if [[ -f "${WORKSPACE_ROOT}/.env.example" ]]; then
    log_info "Found: .env.example"
else
    log_warn "Missing: .env.example"
fi

# ─── Optional: Build images (skip if --skip-build) ───
if [[ "${1:-}" != "--skip-build" ]]; then
    log_info "Building images (this may take a while)..."

    # Backend
    log_info "  Building apocalypse-core..."
    if podman build -f "${WORKSPACE_ROOT}/Apocalypse-chat-core/Containerfile" \
        -t apocalypse-core:latest \
        "${WORKSPACE_ROOT}/Apocalypse-chat-core" &>/dev/null; then
        log_info "  apocalypse-core: OK"
    else
        log_error "  apocalypse-core: BUILD FAILED"
        fail=1
    fi

    # UI
    log_info "  Building apocalypse-ui..."
    if podman build -f "${WORKSPACE_ROOT}/Apocalypse-chat-UI/Containerfile" \
        -t apocalypse-ui:latest \
        "${WORKSPACE_ROOT}/Apocalypse-chat-UI" &>/dev/null; then
        log_info "  apocalypse-ui: OK"
    else
        log_error "  apocalypse-ui: BUILD FAILED"
        fail=1
    fi

    # CLI
    log_info "  Building apocalypse-cli..."
    if podman build -f "${WORKSPACE_ROOT}/apocalypse-cli/Containerfile" \
        -t apocalypse-cli:latest \
        "${WORKSPACE_ROOT}/apocalypse-cli" &>/dev/null; then
        log_info "  apocalypse-cli: OK"
    else
        log_error "  apocalypse-cli: BUILD FAILED"
        fail=1
    fi
fi

# ─── Summary ───
echo ""
if [[ $fail -eq 0 ]]; then
    log_info "All validation checks passed."
    exit 0
else
    log_error "Some validation checks failed. See output above."
    exit 1
fi

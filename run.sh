#!/bin/bash
#
# Wrapper de execução para recon.py
# - Cria o venv na primeira vez (se não existir) e instala as dependências.
# - Ativa o venv automaticamente antes de rodar o script.
# - Desativa o venv automaticamente ao sair (inclusive se o script for
#   interrompido com Ctrl+C).

set -e

VENV_DIR="$HOME/venvs/pentest"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_SCRIPT="$SCRIPT_DIR/recon.py"

# Garante que o venv seja desativado ao sair, não importa como o script termine
cleanup() {
    if command -v deactivate >/dev/null 2>&1; then
        deactivate
        echo "[*] Venv desativado."
    fi
}
trap cleanup EXIT

# Cria o venv se ainda não existir
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Venv não encontrado. Criando em $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    echo "[*] Instalando dependências (python-whois, requests) ..."
    pip install --quiet --upgrade pip
    pip install --quiet python-whois requests
else
    source "$VENV_DIR/bin/activate"
fi

echo "[*] Venv ativado ($VENV_DIR)."
echo ""

python3 "$RECON_SCRIPT"

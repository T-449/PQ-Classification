#!/usr/bin/env bash
# Installs tshark (Wireshark CLI), which pyshark drives to parse .pcapng files
# for the /classify TLS-capture endpoint. The Python deps come from
# requirements.txt (pip install -r requirements.txt); this handles the system
# binary that pip cannot provide.
set -e

if command -v tshark >/dev/null 2>&1; then
    echo "tshark already installed: $(tshark -v | head -1)"
    exit 0
fi

OS="$(uname -s)"
echo "Installing tshark for $OS ..."

case "$OS" in
    Darwin)
        if ! command -v brew >/dev/null 2>&1; then
            echo "Homebrew is required. Install it from https://brew.sh and re-run." >&2
            exit 1
        fi
        brew install wireshark
        ;;
    Linux)
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update
            sudo DEBIAN_FRONTEND=noninteractive apt-get install -y tshark
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y wireshark-cli
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm wireshark-cli
        else
            echo "Unsupported Linux distribution. Install tshark manually." >&2
            exit 1
        fi
        ;;
    *)
        echo "Unsupported OS: $OS. Install tshark manually." >&2
        exit 1
        ;;
esac

if command -v tshark >/dev/null 2>&1; then
    echo "Installed: $(tshark -v | head -1)"
else
    echo "tshark not found on PATH after install — check the output above." >&2
    exit 1
fi

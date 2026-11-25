#!/bin/bash
# Démarrage tethered de l'iPhone SE (N69) sous iOS 16.1, puis installation
# optionnelle de TrollStore via TrollRestore.
#
# Usage : ./boot-tethered.sh [--turdus DIR] [--pteblock FICHIER]
#                          [--trollrestore DIR] [--no-boot] [--dry-run]
#
# Options :
#   --turdus DIR        dossier turdus_m3rula* contenant bin/turdusra1n
#   --pteblock FICHIER  fichier pteblock (sinon : l'unique block/*-current-pteblock2.bin)
#   --trollrestore DIR  installation TrollRestore existante (contient trollstore.py)
#   --no-boot           ne pas démarrer, seulement TrollRestore
#   --dry-run           afficher les commandes sans rien exécuter (pas de sudo)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TURDUS_DIR="${TURDUS_DIR:-}"
PTEBLOCK=""
TROLLRESTORE_DIR="${TROLLRESTORE_DIR:-$SCRIPT_DIR/tools/trollrestore}"
NO_BOOT=0
DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --turdus) TURDUS_DIR="$2"; shift 2 ;;
        --pteblock) PTEBLOCK="$2"; shift 2 ;;
        --trollrestore) TROLLRESTORE_DIR="$2"; shift 2 ;;
        --no-boot) NO_BOOT=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) echo "Option inconnue : $1" >&2; exit 2 ;;
    esac
done

# Commit épinglé de TrollRestore (master, 2024-10-28, CVE-2024-44252 fix).
TR_COMMIT="082f252055"
TR_URL="https://github.com/JJTech0130/TrollRestore"
TR_DEPS=("pymobiledevice3==6.2.0" "click==8.5.1" "bpylist2==4.1.1" "requests==2.34.2" "packaging==26.3" "construct==2.10.70" "construct-typing==0.7.0")

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

# --- Localisation de turdusra1n -------------------------------------------
if [[ -z "$TURDUS_DIR" ]]; then
    for base in "$SCRIPT_DIR" "$HOME/Downloads" "$HOME/Téléchargements"; do
        for cand in "$base"/turdus_m3rula*/; do
            if [[ -x "${cand}bin/turdusra1n" ]]; then
                TURDUS_DIR="${cand%/}"
                break 2
            fi
        done
    done
fi
if [[ -z "$TURDUS_DIR" || ! -x "$TURDUS_DIR/bin/turdusra1n" ]]; then
    echo "Erreur : turdusra1n introuvable. Passez --turdus DIR ou TURDUS_DIR." >&2
    exit 1
fi

# --- Sélection du pteblock -------------------------------------------------
if [[ -z "$PTEBLOCK" ]]; then
    shopt -s nullglob
    blocks=("$TURDUS_DIR"/block/*-current-pteblock2.bin)
    shopt -u nullglob
    if [[ ${#blocks[@]} -eq 0 ]]; then
        echo "Erreur : aucun $TURDUS_DIR/block/*-current-pteblock2.bin. Passez --pteblock FICHIER." >&2
        exit 1
    elif [[ ${#blocks[@]} -eq 1 ]]; then
        PTEBLOCK="${blocks[0]}"
    else
        echo "Plusieurs pteblock trouvés :" >&2
        select b in "${blocks[@]}"; do
            [[ -n "$b" ]] && PTEBLOCK="$b" && break
        done
    fi
fi
[[ -f "$PTEBLOCK" ]] || { echo "Erreur : pteblock introuvable : $PTEBLOCK" >&2; exit 1; }

# --- Questions avant le démarrage ------------------------------------------
echo "Assurez-vous que Localiser mon iPhone est désactivé et que le téléphone"
echo "est déverrouillé et associé (confiance) à cet ordinateur."
read -r -p "Installer TrollStore avec TrollRestore après le démarrage ? [o/N] " rep
DO_TR=0
[[ "$rep" =~ ^[oOyY]$ ]] && DO_TR=1
TR_APP="Tips"
if [[ $DO_TR -eq 1 ]]; then
    read -r -p "App système à remplacer (défaut : Tips) : " rep2
    [[ -n "$rep2" ]] && TR_APP="$rep2"
fi

# --- Démarrage tethered -----------------------------------------------------
if [[ $NO_BOOT -eq 0 ]]; then
    echo "Mettez le téléphone en mode DFU, puis appuyez sur Entrée."
    read -r _
    if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] sudo "%s" -TP "%s"\n' "$TURDUS_DIR/bin/turdusra1n" "$PTEBLOCK"
    else
        sudo "$TURDUS_DIR/bin/turdusra1n" -TP "$PTEBLOCK"
    fi
fi

[[ $DO_TR -eq 0 ]] && { echo "Terminé."; exit 0; }

# --- TrollRestore -----------------------------------------------------------
# Les dépendances épinglées exigent Python >= 3.10 (click 8.5.x, etc.) ;
# /usr/bin/python3 de macOS est en 3.9, on choisit donc l'interpréteur le
# plus récent disponible.
PY310=""
for p in python3.13 python3.12 python3.11 python3.10 python3; do
    for d in "" "/opt/homebrew/bin" "/usr/local/bin"; do
        c="${d:+$d/}$p"
        if command -v "$c" >/dev/null 2>&1 && \
           "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
            PY310="$c"
            break 2
        fi
    done
done
if [[ -z "$PY310" ]]; then
    echo "Erreur : Python 3.10+ introuvable, installe Python 3.10+ (ex. brew install python)." >&2
    exit 1
fi

if [[ ! -f "$TROLLRESTORE_DIR/trollstore.py" ]]; then
    if [[ -d "$TROLLRESTORE_DIR" ]] && [[ -n "$(ls -A "$TROLLRESTORE_DIR" 2>/dev/null)" ]]; then
        echo "Erreur : $TROLLRESTORE_DIR existe déjà mais trollstore.py est absent." >&2
        echo "Supprimez-le ou passez --trollrestore DIR vers une installation valide." >&2
        exit 1
    fi
    echo "Première utilisation : installation de TrollRestore ($TR_COMMIT) dans $TROLLRESTORE_DIR"
    run git clone "$TR_URL" "$TROLLRESTORE_DIR"
    run git -C "$TROLLRESTORE_DIR" checkout "$TR_COMMIT"
fi
if [[ ! -x "$TROLLRESTORE_DIR/venv/bin/python3" ]]; then
    run "$PY310" -m venv "$TROLLRESTORE_DIR/venv"
    run "$TROLLRESTORE_DIR/venv/bin/pip" install "${TR_DEPS[@]}"
fi
PY="$TROLLRESTORE_DIR/venv/bin/python3"

if [[ $NO_BOOT -eq 0 ]]; then
    echo "Attente du téléphone en mode normal (6 minutes max)..."
    deadline=$((SECONDS + 360))
    found=0
    while [[ $SECONDS -lt $deadline ]]; do
        if [[ $DRY_RUN -eq 1 ]]; then
            printf '[dry-run] %s -m pymobiledevice3 usbmux list\n' "$PY"
            found=1; break
        elif "$PY" -m pymobiledevice3 usbmux list 2>/dev/null | grep -qi serial; then
            found=1; break
        elif command -v idevice_id >/dev/null 2>&1 && idevice_id -l 2>/dev/null | grep -q .; then
            found=1; break
        fi
        sleep 5
    done
    if [[ $found -eq 0 ]]; then
        echo "Erreur : téléphone non détecté après 6 minutes." >&2
        exit 1
    fi
    echo "Déverrouillez le téléphone, puis appuyez sur Entrée."
    read -r _
fi

if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] printf %%s\\n "%s" | %s %s/trollstore.py\n' "$TR_APP" "$PY" "$TROLLRESTORE_DIR"
else
    printf '%s\n' "$TR_APP" | "$PY" "$TROLLRESTORE_DIR/trollstore.py"
fi
echo "Terminé."

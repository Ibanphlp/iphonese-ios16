#!/bin/bash
# Capture des logs de l'iPhone pour diagnostiquer l'audio et la camera.
# Usage : ./collect-logs.sh [audio|camera|all]   (Ctrl+C pour arreter)
set -euo pipefail
MODE="${1:-all}"
command -v idevicesyslog >/dev/null || { echo "idevicesyslog introuvable (brew install libimobiledevice)" >&2; exit 1; }
OUT="logs-$MODE-$(date +%Y%m%d-%H%M%S).txt"
case "$MODE" in
    audio)  FILTER='SE-AUDIO|CS42L71|CS35L19|AppleEmbeddedAudio|AppleAE2MCA|mediaserverd|audiomxd|AVAudio|CoreAudio|HAL' ;;
    camera) FILTER='camera|isp|H6|FigCapture|CMCapture|AVCapture|mediaserverd|0x0247|0x9762' ;;
    all)    FILTER='SE-AUDIO|CS42L71|CS35L19|EmbeddedAudio|AE2MCA|mediaserverd|audiomxd|CoreAudio|camera|isp|H6|FigCapture|CMCapture|AVCapture|panic' ;;
    *) echo "Mode inconnu : $MODE (audio|camera|all)" >&2; exit 2 ;;
esac
echo "Enregistrement dans $OUT (Ctrl+C pour arreter)."
echo "Audio : joue un son (haut-parleur), fais un appel (ecouteur), branche un casque, enregistre dans Dictaphone."
echo "Camera : ouvre Appareil photo (arriere puis avant), puis FaceTime deux fois."
idevicesyslog | grep --line-buffered -iE "$FILTER" | tee "$OUT"

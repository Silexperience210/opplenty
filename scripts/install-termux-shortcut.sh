#!/data/data/com.termux/files/usr/bin/bash
# Installs a one-tap opplenty launcher for the Termux:Widget home-screen widget.
# Prereq: install the "Termux:Widget" app (F-Droid), then add its widget to your
# home screen. Run this script once, then tap the "opplenty" shortcut.
set -e
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p ~/.shortcuts
cat > ~/.shortcuts/opplenty <<SH
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
cd "$REPO"
( sleep 2; termux-open-url http://127.0.0.1:8787 ) &
exec python3 -m opplenty.server
SH
chmod +x ~/.shortcuts/opplenty
echo "Raccourci installé: ~/.shortcuts/opplenty"
echo "Ajoute le widget Termux:Widget à ton écran d'accueil, puis tape 'opplenty'."

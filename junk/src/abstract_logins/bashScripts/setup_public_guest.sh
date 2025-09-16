#!/usr/bin/env bash
set -euo pipefail

# Setup a jailed, passwordless "public" user for SFTP-only access.
# Optional: --console-autologin makes "public" the default auto-login on tty1.
# Re-run safe: idempotent where possible and backs up changed files.

CONSOLE_AUTOLOGIN=0
for arg in "$@"; do
  case "$arg" in
    --console-autologin) CONSOLE_AUTOLOGIN=1 ;;
    *) echo "Unknown arg: $arg"; exit 2 ;;
  esac
done

USER=public
JAIL_ROOT=/home/public            # Must be root:root for OpenSSH chroot
JAIL_WRITABLE=${JAIL_ROOT}/data   # Writable subdir owned by public
SSHD_CFG=/etc/ssh/sshd_config
BACKUP_SUFFIX=".$(date +%Y%m%d-%H%M%S).bak"

echo "==> Creating user '$USER' with disabled password (empty password)…"
if ! id -u "$USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$USER"
else
  echo "    User exists, continuing."
fi

# Ensure empty password (required if you really want 'no password'):
passwd -d "$USER"

# Prepare chroot structure
echo "==> Preparing chroot at $JAIL_ROOT …"
mkdir -p "$JAIL_ROOT" "$JAIL_WRITABLE"
# Per sshd chroot rules: chroot dir must be owned by root and not writable
chown root:root "$JAIL_ROOT"
chmod 755 "$JAIL_ROOT"
# Writable subdir for the user’s files
chown "$USER:$USER" "$JAIL_WRITABLE"
chmod 750 "$JAIL_WRITABLE"

# Make the user's real home point to the writable subfolder for convenience
# (SFTP starts at '/', which is $JAIL_ROOT inside the jail. We'll symlink /home -> /data)
if [ ! -e "${JAIL_ROOT}/home" ]; then
  ln -s /data "${JAIL_ROOT}/home"
fi

# Lock the shell so SSH is SFTP-only (no commands)
usermod -s /usr/sbin/nologin "$USER"

# Configure OpenSSH for SFTP chroot
echo "==> Updating sshd_config (backup: ${SSHD_CFG}${BACKUP_SUFFIX}) …"
cp -n "$SSHD_CFG" "${SSHD_CFG}${BACKUP_SUFFIX}"

# Ensure SFTP subsystem line exists and uses internal-sftp
if ! grep -qE '^\s*Subsystem\s+sftp\s+internal-sftp' "$SSHD_CFG"; then
  # Comment out other sftp subsystem lines and add internal-sftp
  sed -i 's/^\s*Subsystem\s\+sftp\s\+.*/# &/' "$SSHD_CFG"
  echo 'Subsystem sftp internal-sftp' >> "$SSHD_CFG"
fi

# Add/replace a Match block for the user
# We’ll make passwordless allowed ONLY for this user. Note: OpenSSH treats empty password as valid
# only if "PermitEmptyPasswords yes" AND "PasswordAuthentication yes" are both true (global or in Match).
if grep -qE '^\s*Match\s+User\s+public\b' "$SSHD_CFG"; then
  # Remove existing block first (from "Match User public" to next "Match" or EOF)
  awk '
    BEGIN{skip=0}
    /^Match[[:space:]]+User[[:space:]]+public$/ {skip=1; next}
    /^Match[[:space:]]/ {if(skip==1){skip=0}}
    skip==0 {print}
  ' "$SSHD_CFG" > "${SSHD_CFG}.tmp"
  mv "${SSHD_CFG}.tmp" "$SSHD_CFG"
fi

cat >> "$SSHD_CFG" <<'EOF'

# --- BEGIN public guest SFTP jail ---
Match User public
    ChrootDirectory /home/public
    ForceCommand internal-sftp
    X11Forwarding no
    AllowTCPForwarding no
    PermitTunnel no
    PasswordAuthentication yes
    PermitEmptyPasswords yes
# --- END public guest SFTP jail ---
EOF

# Restart SSH to apply
echo "==> Restarting sshd…"
systemctl restart ssh || systemctl restart sshd || true

# Optional: console autologin to make 'public' the default local user
if [ "$CONSOLE_AUTOLOGIN" -eq 1 ]; then
  echo "==> Enabling console auto-login for $USER on tty1 …"
  OV_DIR=/etc/systemd/system/getty@tty1.service.d
  OV_FILE=${OV_DIR}/override.conf
  mkdir -p "$OV_DIR"

  if [ ! -f "${OV_FILE}${BACKUP_SUFFIX}" ] && [ -f "$OV_FILE" ]; then
    cp "$OV_FILE" "${OV_FILE}${BACKUP_SUFFIX}"
  fi

  cat > "$OV_FILE" <<EOF
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin ${USER} --noclear %I \$TERM
Type=idle
EOF

  systemctl daemon-reexec
  echo "    Console will auto-login as '$USER' on next tty1 session."
fi

echo "==> Done."
echo
echo "Login vectors configured:"
echo "  • SSH (SFTP-only jail): sftp ${USER}@<server>    (empty password)"
[ "$CONSOLE_AUTOLOGIN" -eq 1 ] && echo "  • Console: auto-login on tty1 as '${USER}'"
echo
echo "User-visible data path inside the jail: /data  (on host: ${JAIL_WRITABLE})"
echo "Revert sshd_config from backup if needed: ${SSHD_CFG}${BACKUP_SUFFIX}"

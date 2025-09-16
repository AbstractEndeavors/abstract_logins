#!/usr/bin/env bash
#
# make_dburl.sh
# ─────────────────────────────────────────────────────────────────────────────
# Simply reads the existing env vars and prints the DATABASE_URL.

# (No validation — we assume those env vars are already set.)

echo "postgresql://${ABSTRACT_DATABASE_USER}:${ABSTRACT_DATABASE_PASSWORD}@${ABSTRACT_DATABASE_HOST}:${ABSTRACT_DATABASE_PORT}/${ABSTRACT_DATABASE_DBNAM}"

echo "Exported DATABASE_URL=${DATABASE_URL}"



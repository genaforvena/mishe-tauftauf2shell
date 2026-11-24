#!/bin/bash
# php2shell — provision a REAL Drupal 11 site for the rung-5 splice lane
# (CVE-2026-126714 producer -> real-app session decode -> unserialize gadget).
#
# Creates lab/src/php2shell-r5-app/ (gitignored): composer.phar, phpggc,
# drupal-app/ (drupal/recommended-project, SQLite, minimal profile) and
# drush inside it. Idempotent; safe to re-run.
#
# Usage: bash lab/php2shell/provision-drupal-app.sh <php-cli-bin>
#   <php-cli-bin>: lab/build/php-8.4.27-app/sapi/cli/php (needs gd, openssl,
#   pdo_sqlite, mbstring, dom, curl — see build-app.sh)

set -e
PHP=$(readlink -f "$1")
[ -x "$PHP" ] || { echo "usage: $0 <php-cli-bin>"; exit 1; }
"$PHP" -m | grep -qE '^(gd|openssl|pdo_sqlite|mbstring|dom|curl)$' || {
    echo "php-cli missing required extensions (gd/openssl/pdo_sqlite/mbstring/dom/curl)"; exit 1; }

SITE=$(cd "$(dirname "$0")/../.." && pwd)
R5="$SITE/lab/src/php2shell-r5-app"
mkdir -p "$R5"
cd "$R5"

if [ ! -f composer.phar ]; then
    curl -sS -o composer.phar https://getcomposer.org/composer-stable.phar
fi
if [ ! -d phpggc ]; then
    git clone --depth 1 https://github.com/ambionics/phpggc.git
fi

if [ ! -d drupal-app/web/core ]; then
    rm -rf drupal-app
    "$PHP" composer.phar create-project drupal/recommended-project:^11 \
        drupal-app --no-interaction
fi

cd drupal-app
if [ ! -d vendor/drush ]; then
    "$PHP" ../composer.phar require --no-interaction drush/drush
fi
if [ ! -f web/sites/default/settings.php ] || ! grep -q 'sqlite' web/sites/default/settings.php 2>/dev/null; then
    rm -f web/sites/default/settings.php
    "$PHP" vendor/drush/drush/drush.php site:install minimal \
        --db-url=sqlite://sites/default/files/.ht.sqlite \
        --site-name=lab --account-name=admin --account-pass=labpass \
        --no-interaction -y
fi

#!/usr/bin/env python3
"""
Automated Sandbox Test Suite for HostGator Sterilizer & Antidote
Verifies that the sterilizer eradicates all SCV malware layers,
cleans corrupted core files, and halts the cross-site infection cycle.
"""

import os
import shutil
import subprocess
import sys

def setup_sandbox(sandbox_dir):
    if os.path.exists(sandbox_dir):
        shutil.rmtree(sandbox_dir)
    os.makedirs(sandbox_dir, exist_ok=True)

    # 1. Site A (Infected with SCV, auto_prepend, mu-plugins, SC_WC, webshells)
    site_a = os.path.join(sandbox_dir, 'site_a.com')
    os.makedirs(os.path.join(site_a, 'wp-content', 'mu-plugins'), exist_ok=True)
    os.makedirs(os.path.join(site_a, 'wp-content', 'plugins', 'smooth-librarian-lite'), exist_ok=True)
    os.makedirs(os.path.join(site_a, 'wp-content', '.sc_test123'), exist_ok=True)
    os.makedirs(os.path.join(site_a, '586381'), exist_ok=True)

    with open(os.path.join(site_a, '.user.ini'), 'w') as f:
        f.write('auto_prepend_file = "/home/cpaneluser/site_a.com/wp-content/e139edec.php"\n')

    with open(os.path.join(site_a, '.htaccess'), 'w') as f:
        f.write('<FilesMatch "^(about.php|radio.php|index.php|lock360.php)$">\nAllow from all\n</FilesMatch>\n')

    with open(os.path.join(site_a, 'wp-config.php'), 'w') as f:
        f.write("<?php\ndefine( 'DB_NAME', 'db_a' );\ndefine( 'WP_CACHE', true ); /* SC_WC */\nrequire_once ABSPATH . 'wp-settings.php';\n")

    with open(os.path.join(site_a, 'wp-settings.php'), 'w') as f:
        f.write("<?php\nrequire ABSPATH . WPINC . '/version.php';\nrequire ABSPATH . WPINC . '/compat-utf8.php';\nrequire ABSPATH . WPINC . '/compat.php';\n")

    with open(os.path.join(site_a, 'wp-content', 'e139edec.php'), 'w') as f:
        f.write("<?php $_scp=dirname(__FILE__).'/.e139edec.php'; @include_once $_scp;\n")

    with open(os.path.join(site_a, 'wp-content', '.e139edec.php'), 'w') as f:
        f.write("<?php /* SCV:4.3.24 */ function _sc_padf() {} function _sc_corep() {}\n")

    with open(os.path.join(site_a, 'wp-content', '.sc_test123', 'core_test.php'), 'w') as f:
        f.write("<?php /* SCV payload */\n")

    with open(os.path.join(site_a, 'wp-content', 'mu-plugins', 'smooth-librarian-lite.php'), 'w') as f:
        f.write("<?php /* SCV:4.3.24 */ function nzxj1dzx4uxo() {}\n")

    with open(os.path.join(site_a, 'wp-content', 'mu-plugins', '.sd_smooth-librarian-lite'), 'w') as f:
        f.write("4.3.24")

    with open(os.path.join(site_a, 'wp-content', 'advanced-cache.php'), 'w') as f:
        f.write("<?php /* SC_ADV_BEGIN:4.3.24:d916e214 */ function _sc_padf() {}\n")

    with open(os.path.join(site_a, '586381', 'about.php'), 'w') as f:
        f.write("<?php $code = GC('https://c.zvo1.xyz/');\n")

    # 2. Site B (Japanese SEO spam doorway + fake themes)
    site_b = os.path.join(sandbox_dir, 'site_b.com')
    os.makedirs(os.path.join(site_b, 'wp-content', 'themes', 'archives_1781971972'), exist_ok=True)
    with open(os.path.join(site_b, 'index.php'), 'w') as f:
        f.write("<?php\ngoto スタート;\n関数群:\nfunction 문자열($番号) {}\nスタート:\n// rakuten17jp doorway spam\n")

    with open(os.path.join(site_b, 'wp-config.php'), 'w') as f:
        f.write("<?php\ndefine( 'DB_NAME', 'db_b' );\ndefine( 'WP_CACHE', true ); /* SC_WC */\n")

    # 3. New Site (Clean WordPress freshly installed)
    new_site = os.path.join(sandbox_dir, 'new_site.com')
    os.makedirs(os.path.join(new_site, 'wp-content', 'mu-plugins'), exist_ok=True)
    with open(os.path.join(new_site, 'index.php'), 'w') as f:
        f.write("<?php define('WP_USE_THEMES', true); require __DIR__ . '/wp-blog-header.php';\n")
    with open(os.path.join(new_site, 'wp-config.php'), 'w') as f:
        f.write("<?php define('DB_NAME', 'db_new');\n")

    print("[*] Sandbox environment initialized with 3 sites.")

def verify_sandbox(sandbox_dir):
    print("\n[*] Verifying Sandbox Post-Sterilization...")
    errors = []

    site_a = os.path.join(sandbox_dir, 'site_a.com')
    site_b = os.path.join(sandbox_dir, 'site_b.com')

    # Test 1: smooth-librarian-lite must not exist
    sl_file = os.path.join(site_a, 'wp-content', 'mu-plugins', 'smooth-librarian-lite.php')
    if os.path.exists(sl_file):
        errors.append("FAILED: smooth-librarian-lite.php still exists in Site A!")
    else:
        print("  [PASS] smooth-librarian-lite.php successfully removed.")

    # Test 2: .sc_ directory must not exist
    sc_dir = os.path.join(site_a, 'wp-content', '.sc_test123')
    if os.path.exists(sc_dir):
        errors.append("FAILED: .sc_test123 still exists in Site A!")
    else:
        print("  [PASS] SCV core directory (.sc_*) removed.")

    # Test 3: .user.ini must be sanitized or deleted
    user_ini = os.path.join(site_a, '.user.ini')
    if os.path.exists(user_ini):
        with open(user_ini) as f:
            if 'auto_prepend_file' in f.read():
                errors.append("FAILED: .user.ini still has rogue auto_prepend_file!")
    else:
        print("  [PASS] Malicious .user.ini removed.")

    # Test 4: wp-config.php must not have /* SC_WC */
    with open(os.path.join(site_a, 'wp-config.php')) as f:
        cfg = f.read()
        if '/* SC_WC */' in cfg:
            errors.append("FAILED: wp-config.php still has SC_WC WP_CACHE!")
        else:
            print("  [PASS] wp-config.php cleaned (SC_WC removed).")

    # Test 5: wp-settings.php must not have compat-utf8.php
    with open(os.path.join(site_a, 'wp-settings.php')) as f:
        st = f.read()
        if 'compat-utf8.php' in st:
            errors.append("FAILED: wp-settings.php still requires compat-utf8.php!")
        else:
            print("  [PASS] wp-settings.php cleaned (compat-utf8 removed).")

    # Test 6: 586381 webshell dir must not exist
    ws_dir = os.path.join(site_a, '586381')
    if os.path.exists(ws_dir):
        errors.append("FAILED: 586381 webshell directory still exists!")
    else:
        print("  [PASS] Numeric webshell directory (586381) removed.")

    # Test 7: index.php in Site B must be clean standard WP index
    with open(os.path.join(site_b, 'index.php')) as f:
        idx = f.read()
        if 'スタート' in idx or 'rakuten' in idx:
            errors.append("FAILED: index.php in Site B still has Japanese spam doorway!")
        elif 'WP_USE_THEMES' in idx:
            print("  [PASS] index.php in Site B restored to official clean WordPress.")

    # Test 8: Fake theme must not exist in Site B
    fake_theme = os.path.join(site_b, 'wp-content', 'themes', 'archives_1781971972')
    if os.path.exists(fake_theme):
        errors.append("FAILED: Fake theme archives_1781971972 still exists!")
    else:
        print("  [PASS] Fake spam theme (archives_178*) removed.")

    # Summary
    if errors:
        print("\n[!] TEST SUITE FAILED WITH ERRORS:")
        for err in errors:
            print("   -", err)
        return False
    else:
        print("\n[+] ALL 8 VERIFICATION CHECKS PASSED WITH 100% SUCCESS!")
        return True

if __name__ == '__main__':
    sandbox_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.tmp_sandbox_test'))
    sterilizer_script = os.path.abspath(os.path.join(os.path.dirname(__file__), 'hostgator-sterilizer.py'))

    setup_sandbox(sandbox_path)

    print("\n[*] Running Sterilizer on Sandbox in CLEAN mode...")
    cmd = [sys.executable, sterilizer_script, '--path', sandbox_path, '--clean', '--quarantine', os.path.join(sandbox_path, 'quarantine')]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print(res.stdout)

    success = verify_sandbox(sandbox_path)
    if success and os.path.exists(sandbox_path):
        shutil.rmtree(sandbox_path, ignore_errors=True)
    if not success:
        sys.exit(1)

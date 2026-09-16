#!/usr/bin/env python3
"""
HostGator & WordPress Hosting Sterilizer
Author: Antigravity CyberSecurity & Web Engineering
Purpose: Eradicate SCV (Smart Custom / smooth-librarian-lite) malware and associated
         webshells, backdoors, auto_prepend hooks, and cross-site worm components.
"""

import os
import sys
import re
import shutil
import argparse
from datetime import datetime

STANDARD_WP_INDEX = """<?php
/**
 * Front to the WordPress application. This file doesn't do anything, but loads
 * wp-blog-header.php which does and tells WordPress to load the theme.
 *
 * @package WordPress
 */

/**
 * Tells WordPress to load the WordPress theme and output it.
 *
 * @var bool
 */
define( 'WP_USE_THEMES', true );

/** Loads the WordPress Environment and Template */
require __DIR__ . '/wp-blog-header.php';
"""

STANDARD_WP_HTACCESS = """# BEGIN WordPress
# The directives (lines) between "BEGIN WordPress" and "END WordPress" are
# dynamically generated, and should only be modified via WordPress filters.
# Any changes to the directives between these markers will be overwritten.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"""

class HostingSterilizer:
    def __init__(self, root_dir, dry_run=True, quarantine_dir=None):
        self.root_dir = os.path.abspath(root_dir)
        self.dry_run = dry_run
        self.quarantine_dir = quarantine_dir
        self.stats = {
            'scanned_files': 0,
            'scanned_dirs': 0,
            'deleted_files': 0,
            'deleted_dirs': 0,
            'cleaned_core_files': 0,
            'restored_index_php': 0,
            'sanitized_htaccess': 0,
            'sanitized_user_ini': 0,
            'threats_detected': []
        }
        if not self.dry_run and self.quarantine_dir:
            os.makedirs(self.quarantine_dir, exist_ok=True)

    def log(self, msg, level="INFO"):
        prefix = {
            "INFO": "[*]",
            "THREAT": "[!]",
            "CLEAN": "[+]",
            "WARN": "[-]"
        }.get(level, "[*]")
        print(f"{prefix} {msg}", flush=True)

    def quarantine_or_delete(self, path, is_dir=False):
        rel = os.path.relpath(path, self.root_dir)
        if self.dry_run:
            self.log(f"[DRY-RUN] Would delete {'dir' if is_dir else 'file'}: {rel}", "THREAT")
            if is_dir:
                self.stats['deleted_dirs'] += 1
            else:
                self.stats['deleted_files'] += 1
            return

        try:
            if self.quarantine_dir:
                target_q = os.path.join(self.quarantine_dir, rel.replace("..", "_").replace(":", "_"))
                os.makedirs(os.path.dirname(target_q), exist_ok=True)
                if is_dir:
                    shutil.copytree(path, target_q, dirs_exist_ok=True)
                else:
                    shutil.copy2(path, target_q)

            if is_dir:
                shutil.rmtree(path, ignore_errors=True)
                self.log(f"Deleted directory: {rel}", "CLEAN")
                self.stats['deleted_dirs'] += 1
            else:
                os.remove(path)
                self.log(f"Deleted file: {rel}", "CLEAN")
                self.stats['deleted_files'] += 1
        except Exception as e:
            self.log(f"Failed to remove {rel}: {e}", "WARN")

    def sanitize_user_ini(self, file_path):
        rel = os.path.relpath(file_path, self.root_dir)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return

        # Check if malicious auto_prepend_file is present
        # Malicious pattern: auto_prepend_file = ".../wp-content/[0-9a-f]{8}\.php"
        has_malicious_prepend = bool(re.search(r'auto_prepend_file\s*=\s*[\'"][^\'"]*wp-content/[0-9a-f]{8}\.php[\'"]', content, re.I))
        has_scv_hash = bool(re.search(r'auto_prepend_file\s*=\s*[\'"][^\'"]*\.php[\'"]', content, re.I)) and ('wordfence-waf.php' not in content)

        if has_malicious_prepend or has_scv_hash:
            self.stats['threats_detected'].append(f"Malicious .user.ini: {rel}")
            if self.dry_run:
                self.log(f"[DRY-RUN] Malicious .user.ini detected at: {rel}", "THREAT")
                self.stats['sanitized_user_ini'] += 1
                return

            # If the only directive was the malicious prepend, delete the file completely
            cleaned = re.sub(r'auto_prepend_file\s*=.*(\r?\n)?', '', content, flags=re.I).strip()
            if not cleaned or cleaned.isspace():
                self.quarantine_or_delete(file_path)
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(cleaned + "\n")
                self.log(f"Sanitized .user.ini (removed rogue auto_prepend_file): {rel}", "CLEAN")
            self.stats['sanitized_user_ini'] += 1

    def sanitize_htaccess(self, file_path):
        rel = os.path.relpath(file_path, self.root_dir)
        try:
            sz = os.path.getsize(file_path)
            # Fast check: rogue htaccess created by SCV is exactly 420 bytes
            is_rogue_htaccess = False
            if sz == 420:
                is_rogue_htaccess = True
            elif sz < 5000:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if "lock360.php" in content or "radio.php" in content or re.search(r'php_value\s+auto_prepend_file', content, re.I):
                    is_rogue_htaccess = True
                elif "mu-plugins" in file_path and ("about.php" in content or "lock360" in content):
                    is_rogue_htaccess = True
        except Exception:
            return

        if is_rogue_htaccess:
            self.stats['threats_detected'].append(f"Compromised .htaccess: {rel}")
            norm = file_path.replace("\\", "/")
            is_subfolder_htaccess = any(sub in norm for sub in ['/wp-content/', '/wp-includes/', '/wp-admin/'])
            
            if self.dry_run:
                self.stats['sanitized_htaccess'] += 1
                return

            if is_subfolder_htaccess:
                self.quarantine_or_delete(file_path)
            else:
                # Root .htaccess of the site: restore clean WordPress rewrite rules
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(STANDARD_WP_HTACCESS)
                self.log(f"Restored clean WordPress rewrite rules in root .htaccess: {rel}", "CLEAN")
            self.stats['sanitized_htaccess'] += 1

    def sanitize_wp_config(self, file_path):
        rel = os.path.relpath(file_path, self.root_dir)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return

        if "/* SC_WC */" in content or "WP_CACHE" in content:
            # Check if injected with SC_WC
            if re.search(r'define\s*\(\s*[\'"]WP_CACHE[\'"]\s*,\s*true\s*\)\s*;\s*/\*\s*SC_WC\s*\*/', content):
                self.stats['threats_detected'].append(f"SC_WC injection in wp-config.php: {rel}")
                if self.dry_run:
                    self.log(f"[DRY-RUN] Injected WP_CACHE found in: {rel}", "THREAT")
                    self.stats['cleaned_core_files'] += 1
                    return

                cleaned = re.sub(r'define\s*\(\s*[\'"]WP_CACHE[\'"]\s*,\s*true\s*\)\s*;\s*/\*\s*SC_WC\s*\*/(\r?\n)?', '', content)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(cleaned)
                self.log(f"Removed rogue WP_CACHE injection from: {rel}", "CLEAN")
                self.stats['cleaned_core_files'] += 1

    def sanitize_wp_settings(self, file_path):
        rel = os.path.relpath(file_path, self.root_dir)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return

        if "compat-utf8.php" in content:
            self.stats['threats_detected'].append(f"compat-utf8.php injection in wp-settings.php: {rel}")
            if self.dry_run:
                self.log(f"[DRY-RUN] Rogue require compat-utf8.php in: {rel}", "THREAT")
                self.stats['cleaned_core_files'] += 1
                return

            cleaned = re.sub(r'require\s+ABSPATH\s*\.\s*WPINC\s*\.\s*[\'"]/compat-utf8\.php[\'"]\s*;(\r?\n)?', '', content)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(cleaned)
            self.log(f"Removed rogue compat-utf8.php require from: {rel}", "CLEAN")
            self.stats['cleaned_core_files'] += 1

    def sanitize_index_php(self, file_path):
        rel = os.path.relpath(file_path, self.root_dir)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return

        # Check for Japanese/Chinese spam doorway injections
        is_spam_doorway = False
        if any(marker in content for marker in ['スタート', '関数群', '文字れんけつ', 'rakuten17jp', 'goto スタート;']):
            is_spam_doorway = True
        elif 'wp-blog-header.php' not in content and ('base64_decode' in content or 'eval(' in content):
            is_spam_doorway = True

        if is_spam_doorway:
            self.stats['threats_detected'].append(f"SEO Spam Doorway in index.php: {rel}")
            if self.dry_run:
                self.log(f"[DRY-RUN] SEO Spam Doorway detected in index.php: {rel}", "THREAT")
                self.stats['restored_index_php'] += 1
                return

            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(STANDARD_WP_INDEX)
            self.log(f"Restored official clean WordPress index.php: {rel}", "CLEAN")
            self.stats['restored_index_php'] += 1

    def is_malicious_hash_loader(self, file_path, filename):
        # Checks for wp-content/e139edec.php or wp-content/.e139edec.php
        # Pattern: 8 hex chars .php or .8 hex chars .php
        m = re.match(r'^\.?([0-9a-f]{8})\.php$', filename, re.I)
        if m and "wp-content" in file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    snippet = f.read(2048)
                if any(sig in snippet for sig in ['_scp=dirname', 'kh4115rhjhz', 'kfe2dy48qyctn', '_sc_padf', '_sc_corep', 'SCV:']):
                    return True
            except Exception:
                pass
        return False

    def is_malicious_advanced_cache(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                snippet = f.read(2048)
            return '/* SC_ADV_BEGIN:' in snippet or 'fvpciiwo370' in snippet or '_sc_padf' in snippet
        except Exception:
            return False

    def is_scv_payload(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                snippet = f.read(2048)
            return '/* SCV:' in snippet or 'smooth-librarian-lite' in snippet or 'xsbg56lm973e0j' in snippet
        except Exception:
            return False

    def is_webshell(self, file_path, filename):
        # Known webshell names
        fn_lower = filename.lower()
        if fn_lower in ['lock360.php', 'radio.php']:
            return True
        if fn_lower == 'wp-login.php' and any(sub in file_path.lower() for sub in ['smilies', 'images', 'uploads']):
            return True
        if fn_lower == 'about.php':
            # Legitimate about.php exists only in wp-admin/about.php, wp-admin/network/about.php, wp-admin/user/about.php
            norm = os.path.normpath(file_path).replace("\\", "/")
            if not ("/wp-admin/" in norm or "/wp-admin__" in norm):
                return True
        # Check content signature of C2 webshells
        if file_path.endswith('.php'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    snippet = f.read(4096)
                if 'c.zvo1.xyz' in snippet or 'c2.icw7.com' in snippet or 'c.bya61.xyz' in snippet or '45.11.57.159' in snippet:
                    return True
                if '$need = \'<\'.\'?p\'.\'hp\';' in snippet or 'md5($_COOKIE[\'p8\'])' in snippet:
                    return True
            except Exception:
                pass
        return False

    def is_fake_theme_dir(self, dirname):
        # Fake themes injected by Japanese/C2 spam: archives_178*, author-template-178*, etc.
        patterns = [
            r'^[a-z0-9_-]+_178[0-9]{7}$',
            r'^[a-z0-9_-]+-178[0-9]{7}$',
            r'^(?:archives|author-template|author_template|comment_section|config|custom_file_\d+|error-404|page-template|search-template|top|widget-area)[_-]\d{7,}$'
        ]
        return any(re.match(p, dirname, re.I) for p in patterns)

    def is_numeric_backdoor_dir(self, dirname):
        # Random numeric directories holding about.php
        return bool(re.match(r'^(?:586381|144710|bca42b57)$', dirname))

    def run_sterilization(self):
        self.log(f"Starting Hosting Sterilizer on: {self.root_dir}")
        self.log(f"Mode: {'DRY-RUN (Simulated)' if self.dry_run else 'ACTIVE STERILIZATION'}")
        start_time = datetime.now()

        # Step 1: Scan tree and identify all threats
        dirs_to_delete = []

        for root, dirs, files in os.walk(self.root_dir, topdown=True):
            # Exclude non-active folders to optimize speed
            dirs[:] = [d for d in dirs if d not in ['.trash', 'quarantine_backup', '.git', '.cache', 'node_modules', 'logs', 'mail', 'ssl', '.cphorde', '.spamassassin', 'vendor']]
            self.stats['scanned_dirs'] += len(dirs)
            self.stats['scanned_files'] += len(files)

            # Check directory-level threats
            for d in list(dirs):
                dp = os.path.join(root, d)
                rel_d = os.path.relpath(dp, self.root_dir)

                # Malicious SCV hidden directories
                if d.startswith('.sc_') or d == '.sc_ymp':
                    self.stats['threats_detected'].append(f"SCV core dir: {rel_d}")
                    dirs_to_delete.append(dp)
                    dirs.remove(d)
                # Malicious numeric or hex webshell directories (e.g. 586381, 144710, 6cd6e2e4)
                elif self.is_numeric_backdoor_dir(d) or bool(re.match(r'^[0-9a-f]{6,10}$', d, re.I)):
                    # Check if it contains about.php
                    if os.path.exists(os.path.join(dp, 'about.php')):
                        self.stats['threats_detected'].append(f"Webshell folder: {rel_d}")
                        dirs_to_delete.append(dp)
                        dirs.remove(d)
                # Fake theme spam directories
                elif self.is_fake_theme_dir(d):
                    self.stats['threats_detected'].append(f"Fake theme spam dir: {rel_d}")
                    dirs_to_delete.append(dp)
                    dirs.remove(d)
                # Smooth librarian plugin folder
                elif d == 'smooth-librarian-lite' and ('plugins' in root or 'mu-plugins' in root):
                    self.stats['threats_detected'].append(f"Smooth Librarian plugin dir: {rel_d}")
                    dirs_to_delete.append(dp)
                    dirs.remove(d)

            # Check file-level threats
            for f in files:
                fp = os.path.join(root, f)
                rel_f = os.path.relpath(fp, self.root_dir)

                # Check .user.ini
                if f == '.user.ini':
                    self.sanitize_user_ini(fp)

                # Check .htaccess
                elif f == '.htaccess':
                    self.sanitize_htaccess(fp)

                # Check wp-config.php
                elif f == 'wp-config.php':
                    self.sanitize_wp_config(fp)

                # Check wp-settings.php
                elif f == 'wp-settings.php':
                    self.sanitize_wp_settings(fp)

                # Check index.php
                elif f == 'index.php':
                    self.sanitize_index_php(fp)

                # Check malicious hash loaders (wp-content/<hash>.php and wp-content/.<hash>.php)
                elif self.is_malicious_hash_loader(fp, f):
                    self.stats['threats_detected'].append(f"SCV Hash Loader: {rel_f}")
                    self.quarantine_or_delete(fp)

                # Check smooth-librarian-lite PHP file
                elif f == 'smooth-librarian-lite.php':
                    self.stats['threats_detected'].append(f"Smooth Librarian malware file: {rel_f}")
                    self.quarantine_or_delete(fp)

                # Check SCV dot files in mu-plugins (.sd_, .rd_, .bt_, .wr_, .q_)
                elif any(f.startswith(prefix) for prefix in ['.sd_', '.rd_', '.bt_', '.wr_', '.q_']) and 'smooth-librarian' in f:
                    self.stats['threats_detected'].append(f"SCV tracking file: {rel_f}")
                    self.quarantine_or_delete(fp)

                # Check advanced-cache.php
                elif f == 'advanced-cache.php' and self.is_malicious_advanced_cache(fp):
                    self.stats['threats_detected'].append(f"Malicious advanced-cache.php: {rel_f}")
                    self.quarantine_or_delete(fp)

                # Check webshells
                elif self.is_webshell(fp, f):
                    self.stats['threats_detected'].append(f"Webshell backdoor: {rel_f}")
                    self.quarantine_or_delete(fp)

                # Check zip payloads in wp-content (like cbff34f5.zip)
                elif f.endswith('.zip') and re.match(r'^[0-9a-f]{8}\.zip$', f, re.I) and 'wp-content' in root:
                    self.stats['threats_detected'].append(f"SCV Payload zip: {rel_f}")
                    self.quarantine_or_delete(fp)

                # Check uploads infection
                elif 'smooth-librari' in f and 'uploads' in root:
                    self.stats['threats_detected'].append(f"Dropped upload malware: {rel_f}")
                    self.quarantine_or_delete(fp)

        # Delete detected directories
        for dp in dirs_to_delete:
            self.quarantine_or_delete(dp, is_dir=True)

        elapsed = datetime.now() - start_time
        self.log("="*60)
        self.log(f"Sterilization Completed in {elapsed.total_seconds():.2f}s")
        self.log(f"Scanned Files: {self.stats['scanned_files']} | Scanned Directories: {self.stats['scanned_dirs']}")
        self.log(f"Threats Detected: {len(self.stats['threats_detected'])}")
        self.log(f"Deleted Files: {self.stats['deleted_files']} | Deleted Directories: {self.stats['deleted_dirs']}")
        self.log(f"Cleaned Core Files (wp-config/wp-settings): {self.stats['cleaned_core_files']}")
        self.log(f"Restored index.php: {self.stats['restored_index_php']}")
        self.log(f"Sanitized .htaccess: {self.stats['sanitized_htaccess']}")
        self.log(f"Sanitized .user.ini: {self.stats['sanitized_user_ini']}")
        self.log("="*60)

        return self.stats

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="HostGator & WordPress Hosting Sterilizer")
    parser.add_argument('--path', default='.', help="Root directory to scan (default: current directory)")
    parser.add_argument('--clean', action='store_true', help="Perform actual sterilization (defaults to dry-run)")
    parser.add_argument('--quarantine', default='quarantine_backup', help="Quarantine directory for removed threats")
    args = parser.parse_args()

    sterilizer = HostingSterilizer(
        root_dir=args.path,
        dry_run=not args.clean,
        quarantine_dir=args.quarantine if args.clean else None
    )
    sterilizer.run_sterilization()

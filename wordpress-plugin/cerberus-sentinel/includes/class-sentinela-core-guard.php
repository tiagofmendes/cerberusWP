<?php
/**
 * Sentinel Core Guard
 * Monitora e restaura a integridade dos arquivos vitais do WordPress.
 */

defined('ABSPATH') || exit;

class Sentinela_Core_Guard {

    private static $standardIndex = "<?php\n/**\n * Front to the WordPress application.\n *\n * @package WordPress\n */\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n";

    private static $standardHtaccess = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n";

    public static function audit_core_files() {
        $issues = [];

        // 1. wp-config.php
        $wpConfigPath = ABSPATH . 'wp-config.php';
        if (!file_exists($wpConfigPath) && file_exists(dirname(ABSPATH) . '/wp-config.php')) {
            $wpConfigPath = dirname(ABSPATH) . '/wp-config.php';
        }

        if (file_exists($wpConfigPath)) {
            $configContent = @file_get_contents($wpConfigPath);
            if (strpos($configContent, '/* SC_WC */') !== false) {
                $issues[] = [
                    'file' => 'wp-config.php',
                    'path' => $wpConfigPath,
                    'severity' => 'HIGH',
                    'type' => 'SC_WC_INJECTION',
                    'description' => 'Injeção de WP_CACHE maliciosa detectada (usada para acionar o backdoor advanced-cache.php).'
                ];
            }
        }

        // 2. wp-settings.php
        $wpSettingsPath = ABSPATH . 'wp-settings.php';
        if (file_exists($wpSettingsPath)) {
            $settingsContent = @file_get_contents($wpSettingsPath);
            if (strpos($settingsContent, 'compat-utf8.php') !== false) {
                $issues[] = [
                    'file' => 'wp-settings.php',
                    'path' => $wpSettingsPath,
                    'severity' => 'CRITICAL',
                    'type' => 'COMPAT_UTF8_INJECTION',
                    'description' => 'Chamada não autorizada a compat-utf8.php na linha 35 (derruba o site e injeta código).'
                ];
            }
        }

        // 3. index.php
        $indexPath = ABSPATH . 'index.php';
        if (file_exists($indexPath)) {
            $indexContent = @file_get_contents($indexPath);
            if (strpos($indexContent, 'スタート') !== false || strpos($indexContent, 'rakuten17jp') !== false || (strpos($indexContent, 'wp-blog-header.php') === false && strpos($indexContent, 'base64_decode') !== false)) {
                $issues[] = [
                    'file' => 'index.php',
                    'path' => $indexPath,
                    'severity' => 'CRITICAL',
                    'type' => 'SEO_SPAM_DOORWAY',
                    'description' => 'Doorway de SEO Spam Japonês / Rakuten injetado na raiz do site.'
                ];
            }
        }

        // 4. .user.ini
        $userIniPaths = [ABSPATH . '.user.ini', WP_CONTENT_DIR . '/.user.ini'];
        foreach ($userIniPaths as $uip) {
            if (file_exists($uip)) {
                $iniContent = @file_get_contents($uip);
                if (preg_match('/auto_prepend_file\s*=\s*[\'"][^\'"]*\.php[\'"]/i', $iniContent) && strpos($iniContent, 'wordfence-waf.php') === false) {
                    $issues[] = [
                        'file' => basename($uip),
                        'path' => $uip,
                        'severity' => 'CRITICAL',
                        'type' => 'MALICIOUS_AUTO_PREPEND',
                        'description' => 'Diretiva auto_prepend_file apontando para dropper de malware.'
                    ];
                }
            }
        }

        // 5. advanced-cache.php
        $advCache = WP_CONTENT_DIR . '/advanced-cache.php';
        if (file_exists($advCache)) {
            $advContent = @file_get_contents($advCache, false, null, 0, 1024);
            if ($advContent && (strpos($advContent, '/* SC_ADV_BEGIN:') !== false || strpos($advContent, '_sc_padf') !== false)) {
                $issues[] = [
                    'file' => 'advanced-cache.php',
                    'path' => $advCache,
                    'severity' => 'CRITICAL',
                    'type' => 'SC_ADVANCED_CACHE',
                    'description' => 'Arquivo advanced-cache.php sequestrado pelo motor SCV.'
                ];
            }
        }

        // 6. .htaccess
        $htaccessPath = ABSPATH . '.htaccess';
        if (file_exists($htaccessPath)) {
            $htContent = @file_get_contents($htaccessPath);
            if (strpos($htContent, 'lock360.php') !== false || strpos($htContent, 'radio.php') !== false || preg_match('/php_value\s+auto_prepend_file/i', $htContent)) {
                $issues[] = [
                    'file' => '.htaccess',
                    'path' => $htaccessPath,
                    'severity' => 'HIGH',
                    'type' => 'COMPROMISED_HTACCESS',
                    'description' => 'Regras adulteradas no .htaccess permitindo acesso a webshells ocultos.'
                ];
            }
        }

        return $issues;
    }

    public static function self_heal_all() {
        $repaired = [];

        // Heal wp-config.php
        $wpConfigPath = ABSPATH . 'wp-config.php';
        if (!file_exists($wpConfigPath) && file_exists(dirname(ABSPATH) . '/wp-config.php')) {
            $wpConfigPath = dirname(ABSPATH) . '/wp-config.php';
        }
        if (file_exists($wpConfigPath)) {
            $cfg = @file_get_contents($wpConfigPath);
            if (strpos($cfg, '/* SC_WC */') !== false) {
                $clean = preg_replace('/define\s*\(\s*[\'"]WP_CACHE[\'"]\s*,\s*true\s*\)\s*;\s*\/\*\s*SC_WC\s*\*\/\r?\n?/', '', $cfg);
                @file_put_contents($wpConfigPath, $clean);
                $repaired[] = 'wp-config.php (Removido WP_CACHE SC_WC)';
            }
        }

        // Heal wp-settings.php
        $wpSettingsPath = ABSPATH . 'wp-settings.php';
        if (file_exists($wpSettingsPath)) {
            $st = @file_get_contents($wpSettingsPath);
            if (strpos($st, 'compat-utf8.php') !== false) {
                $clean = preg_replace('/require\s+ABSPATH\s*\.\s*WPINC\s*\.\s*[\'"]\/compat-utf8\.php[\'"]\s*;\r?\n?/', '', $st);
                @file_put_contents($wpSettingsPath, $clean);
                $repaired[] = 'wp-settings.php (Removido require compat-utf8.php)';
            }
        }

        // Heal index.php
        $indexPath = ABSPATH . 'index.php';
        if (file_exists($indexPath)) {
            $idx = @file_get_contents($indexPath);
            if (strpos($idx, 'スタート') !== false || strpos($idx, 'rakuten17jp') !== false || (strpos($idx, 'wp-blog-header.php') === false && strpos($idx, 'base64_decode') !== false)) {
                @file_put_contents($indexPath, self::$standardIndex);
                $repaired[] = 'index.php (Restaurado index padrão do WordPress)';
            }
        }

        // Heal .user.ini
        $userIniPaths = [ABSPATH . '.user.ini', WP_CONTENT_DIR . '/.user.ini'];
        foreach ($userIniPaths as $uip) {
            if (file_exists($uip)) {
                $ini = @file_get_contents($uip);
                if (preg_match('/auto_prepend_file\s*=\s*[\'"][^\'"]*\.php[\'"]/i', $ini) && strpos($ini, 'wordfence-waf.php') === false) {
                    $cleaned = trim(preg_replace('/auto_prepend_file\s*=.*(\r?\n)?/i', '', $ini));
                    if (empty($cleaned)) {
                        @unlink($uip);
                    } else {
                        @file_put_contents($uip, $cleaned . "\n");
                    }
                    $repaired[] = basename($uip) . ' (Removido auto_prepend_file malicioso)';
                }
            }
        }

        // Remove rogue advanced-cache.php
        $advCache = WP_CONTENT_DIR . '/advanced-cache.php';
        if (file_exists($advCache)) {
            $adv = @file_get_contents($advCache, false, null, 0, 1024);
            if ($adv && (strpos($adv, '/* SC_ADV_BEGIN:') !== false || strpos($adv, '_sc_padf') !== false)) {
                @unlink($advCache);
                $repaired[] = 'advanced-cache.php (Arquivo sequestrado excluído)';
            }
        }

        // Heal .htaccess
        $htaccessPath = ABSPATH . '.htaccess';
        if (file_exists($htaccessPath)) {
            $ht = @file_get_contents($htaccessPath);
            if (strpos($ht, 'lock360.php') !== false || strpos($ht, 'radio.php') !== false || preg_match('/php_value\s+auto_prepend_file/i', $ht)) {
                @file_put_contents($htaccessPath, self::$standardHtaccess);
                $repaired[] = '.htaccess (Regras restauradas para o padrão WordPress)';
            }
        }

        return $repaired;
    }
}

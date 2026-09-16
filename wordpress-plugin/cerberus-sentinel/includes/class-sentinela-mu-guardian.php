<?php
/**
 * Sentinel MU-Plugin Guardian
 * Protege, audita e imuniza o diretório wp-content/mu-plugins/
 */

defined('ABSPATH') || exit;

class Sentinela_MU_Guardian {

    public static function get_mu_dir() {
        return defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : (WP_CONTENT_DIR . '/mu-plugins');
    }

    public static function audit_mu_plugins() {
        $muDir = self::get_mu_dir();
        $findings = [];

        if (!is_dir($muDir)) {
            return $findings;
        }

        $items = @scandir($muDir);
        if (!$items) return $findings;

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $fullPath = $muDir . '/' . $item;

            // smooth-librarian-lite
            if (strpos($item, 'smooth-librarian') !== false) {
                $findings[] = [
                    'file' => $item,
                    'path' => $fullPath,
                    'type' => 'SCV_MALWARE_DROP',
                    'severity' => 'CRITICAL',
                    'description' => 'Arquivo do worm smooth-librarian-lite detectado no diretório de execução obrigatória.'
                ];
            }

            // Rogue .htaccess
            if ($item === '.htaccess') {
                $sz = @filesize($fullPath);
                if ($sz === 420 || @strpos(@file_get_contents($fullPath), 'lock360') !== false) {
                    $findings[] = [
                        'file' => '.htaccess',
                        'path' => $fullPath,
                        'type' => 'ROGUE_HTACCESS',
                        'severity' => 'HIGH',
                        'description' => 'Arquivo .htaccess adulterado em mu-plugins permitindo execução de webshells.'
                    ];
                }
            }

            // Rogue hidden files (.sc_*, .wr_*, .sd_*, .rd_*, .bt_*)
            if (preg_match('/^\.(?:sc|wr|sd|rd|bt|q)_/i', $item)) {
                $findings[] = [
                    'file' => $item,
                    'path' => $fullPath,
                    'type' => 'SCV_TRACKING_MARKER',
                    'severity' => 'HIGH',
                    'description' => 'Marcador ou payload oculto do SCV.'
                ];
            }
        }

        return $findings;
    }

    public static function install_vaccine() {
        $muDir = self::get_mu_dir();
        if (!is_dir($muDir)) {
            @mkdir($muDir, 0755, true);
        }

        $vaccineSource = dirname(__FILE__) . '/../mu-antidote/000-antidoto-vaccine.php';
        $vaccineDest = $muDir . '/000-antidoto-vaccine.php';

        if (file_exists($vaccineSource)) {
            $code = @file_get_contents($vaccineSource);
            if ($code) {
                // Insere cabeçalho Plugin Name no destino mu-plugins para exibição no painel WP
                $code = str_replace('Vaccine Name:', 'Plugin Name:', $code);
                @file_put_contents($vaccineDest, $code);
            } else {
                @copy($vaccineSource, $vaccineDest);
            }
            @chmod($vaccineDest, 0644);
            return true;
        }

        return false;
    }

    public static function purge_threats() {
        $threats = self::audit_mu_plugins();
        $purged = [];

        foreach ($threats as $t) {
            @chmod($t['path'], 0666);
            if (is_dir($t['path'])) {
                @rmdir($t['path']);
            } else {
                @unlink($t['path']);
            }
            $purged[] = $t['file'];
        }

        // Garante que a vacina esteja instalada
        self::install_vaccine();

        return $purged;
    }
}

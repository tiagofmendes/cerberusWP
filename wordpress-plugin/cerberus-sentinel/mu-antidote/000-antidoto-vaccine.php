<?php
/**
 * Vaccine Name: 000 Antídoto & Vacina Sentinela (Must-Use)
 * Description: Vacina de ultra-alta prioridade que executa antes de qualquer plugin, bloqueando o worm SCV e desarmando auto_prepend_file.
 * Version: 1.0.0
 * Author: Antigravity CyberSecurity
 */

defined('ABSPATH') || exit;

// 1. Desarma tentativas de injeção SCV em memória e bloqueia spawn de wp-cron bloqueante
if (!defined('SC_CORE_BOOT_VER')) {
    define('SC_CORE_BOOT_VER', '99.99.99'); // Bloqueia o bootloader do SCV simulando versão superior
}
$GLOBALS['sc_boot_ver'] = '99.99.99';

if (!defined('DISABLE_WP_CRON')) {
    define('DISABLE_WP_CRON', true);
}

// 2. Trava de Execução de Backdoors e Requisições Maliciosas C2
if (isset($_REQUEST['api']) && isset($_REQUEST['ac']) && isset($_REQUEST['path']) && isset($_REQUEST['t'])) {
    http_response_code(403);
    die('Forbidden: Intrusion Attempt Blocked by Antidote Sentinel.');
}

// 3. Verificação e Imunização do Diretório mu-plugins
(function() {
    $muDir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : (WP_CONTENT_DIR . '/mu-plugins');
    if (!is_dir($muDir)) return;

    $rogueFiles = [
        $muDir . '/smooth-librarian-lite.php',
        $muDir . '/.bt_smooth-librarian-lite',
        $muDir . '/.rd_smooth-librarian-lite',
        $muDir . '/.sd_smooth-librarian-lite',
        $muDir . '/.wr_smooth-librarian-lite',
        $muDir . '/.q_smooth-librarian-lite'
    ];

    foreach ($rogueFiles as $rf) {
        if (@file_exists($rf)) {
            @chmod($rf, 0666);
            @unlink($rf);
        }
    }

    // Se houver .htaccess espúrio em mu-plugins, remova-o
    $muHtaccess = $muDir . '/.htaccess';
    if (@file_exists($muHtaccess) && @filesize($muHtaccess) === 420) {
        @unlink($muHtaccess);
    }
})();

// 4. Neutraliza tentativa de camuflagem de usuários no banco
add_action('init', function() {
    global $wp_filter;
    if (isset($wp_filter['pre_user_query'])) {
        foreach ($wp_filter['pre_user_query']->callbacks as $priority => $callbacks) {
            foreach ($callbacks as $idx => $data) {
                if (is_string($idx) && (preg_match('/^[a-z0-9_]{14,}$/i', $idx) || strpos($idx, 'sc_') !== false)) {
                    remove_filter('pre_user_query', $idx, $priority);
                }
            }
        }
    }
}, 1);

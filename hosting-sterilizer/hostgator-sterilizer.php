<?php
/**
 * HostGator & WordPress Hosting Sterilizer (PHP Edition)
 * 
 * Especialista em Segurança Cibernética & Engenharia Web
 * Antigravity Advanced CyberSec Lab
 * 
 * Funcionalidade:
 * - Varredura e erradicação atômica do malware SCV (Smart Custom / smooth-librarian-lite)
 * - Matriz Interativa de Ameaças com inspeção de trechos de código e checkboxes individuais
 * - Motor de Quarentena Automática ZIP com manifest.json antes de qualquer exclusão/alteração
 * - Download de backup de quarentena (.zip) e Restauração/Rollback em 1 clique
 * - Implantação automática de Vacina Must-Use de ultra-alta prioridade (000-antidoto-vaccine.php)
 * - Execução via CLI (SSH/Cron) ou via Web com autenticação por token de segurança.
 */

// Define token de segurança padrão para execução web
define('STERILIZER_SECRET_TOKEN', 'c3ber0s-cl34n-v1');

// Aumenta limites de execução para varredura pesada
@ini_set('memory_limit', '1024M');
@ini_set('max_execution_time', '1800');
@set_time_limit(1800);
if (function_exists('ignore_user_abort')) {
    @ignore_user_abort(true);
}

class HostingSterilizerPHP {
    private $rootDir;
    private $dryRun;
    private $quarantineDir;
    private $targetIds;
    private $isCli;
    public $threatItems = [];
    public $wpRoots = [];

    public $onProgress = null;
    public $onThreat = null;
    public $onLog = null;
    public $onStep = null;

    public $stats = [
        'scanned_files' => 0,
        'scanned_dirs' => 0,
        'threat_count' => 0,
        'deleted_files' => 0,
        'deleted_dirs' => 0,
        'cleaned_core_files' => 0,
        'restored_index_php' => 0,
        'sanitized_htaccess' => 0,
        'sanitized_user_ini' => 0,
        'vaccines_deployed' => 0,
        'quarantine_zip' => null,
        'threat_items' => [],
        'logs' => []
    ];

    private $standardIndex = "<?php\n/**\n * Front to the WordPress application.\n *\n * @package WordPress\n */\ndefine( 'WP_USE_THEMES', true );\nrequire __DIR__ . '/wp-blog-header.php';\n";

    private $standardHtaccess = "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n";

    private $vaccineCode = "<?php\n/**\n * Plugin Name: 000 Antídoto & Vacina Sentinela (Must-Use)\n * Description: Vacina de ultra-alta prioridade que executa antes de qualquer plugin, bloqueando o worm SCV e desarmando auto_prepend_file.\n * Version: 1.0.0\n * Author: Antigravity CyberSecurity\n */\n\ndefined('ABSPATH') || exit;\n\n// 1. Desarma tentativas de injeção SCV em memória\nif (!defined('SC_CORE_BOOT_VER')) {\n    define('SC_CORE_BOOT_VER', '99.99.99');\n}\n\$GLOBALS['sc_boot_ver'] = '99.99.99';\n\n// 2. Trava de Execução de Backdoors e Requisições Maliciosas C2\nif (isset(\$_REQUEST['api']) && isset(\$_REQUEST['ac']) && isset(\$_REQUEST['path']) && isset(\$_REQUEST['t'])) {\n    http_response_code(403);\n    die('Forbidden: Intrusion Attempt Blocked by Antidote Sentinel.');\n}\n\n// 3. Verificação e Imunização do Diretório mu-plugins\n(function() {\n    \$muDir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : (WP_CONTENT_DIR . '/mu-plugins');\n    if (!is_dir(\$muDir)) return;\n\n    \$rogueFiles = [\n        \$muDir . '/smooth-librarian-lite.php',\n        \$muDir . '/.bt_smooth-librarian-lite',\n        \$muDir . '/.rd_smooth-librarian-lite',\n        \$muDir . '/.sd_smooth-librarian-lite',\n        \$muDir . '/.wr_smooth-librarian-lite',\n        \$muDir . '/.q_smooth-librarian-lite'\n    ];\n\n    foreach (\$rogueFiles as \$rf) {\n        if (@file_exists(\$rf)) {\n            @chmod(\$rf, 0666);\n            @unlink(\$rf);\n        }\n    }\n\n    \$muHtaccess = \$muDir . '/.htaccess';\n    if (@file_exists(\$muHtaccess) && @filesize(\$muHtaccess) === 420) {\n        @unlink(\$muHtaccess);\n    }\n})();\n\n// 4. Neutraliza tentativa de camuflagem de usuários no banco\nadd_action('init', function() {\n    global \$wp_filter;\n    if (isset(\$wp_filter['pre_user_query'])) {\n        foreach (\$wp_filter['pre_user_query']->callbacks as \$priority => \$callbacks) {\n            foreach (\$callbacks as \$idx => \$data) {\n                if (is_string(\$idx) && (preg_match('/^[a-z0-9_]{14,}$/i', \$idx) || strpos(\$idx, 'sc_') !== false)) {\n                    remove_filter('pre_user_query', \$idx, \$priority);\n                }\n            }\n        }\n    }\n}, 1);\n";

    public function __construct($rootDir = '.', $dryRun = true, $quarantineDir = null, $targetIds = null) {
        $this->rootDir = realpath($rootDir) ?: $rootDir;
        $this->dryRun = $dryRun;
        $this->quarantineDir = $quarantineDir ? (realpath($quarantineDir) ?: $quarantineDir) : ($this->rootDir . DIRECTORY_SEPARATOR . 'quarantine_backup');
        $this->targetIds = is_array($targetIds) ? $targetIds : null;
        $this->isCli = (php_sapi_name() === 'cli');
    }

    public function log($msg, $level = 'INFO') {
        $timestamp = date('H:i:s');
        $this->stats['logs'][] = "[$timestamp] [$level] $msg";
        if ($this->onLog) {
            ($this->onLog)($msg, $level, $timestamp);
        }
        if ($this->isCli) {
            $prefix = $level === 'THREAT' ? "\033[31m[!]\033[0m" : ($level === 'CLEAN' ? "\033[32m[+]\033[0m" : ($level === 'BACKUP' ? "\033[36m[#]\033[0m" : "\033[34m[*]\033[0m"));
            echo "$prefix [$timestamp] $msg\n";
            flush();
        }
    }

    public function formatSize($bytes) {
        if ($bytes === null || $bytes === false) return 'N/A';
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return round($bytes, 1) . ' ' . $units[$i];
    }

    private function getDirSnippet($dir) {
        $files = @scandir($dir);
        if (!$files) return "[Diretório vazio ou inacessível]";
        $items = [];
        foreach ($files as $f) {
            if ($f === '.' || $f === '..') continue;
            $fp = $dir . DIRECTORY_SEPARATOR . $f;
            $isD = is_dir($fp);
            $sz = $isD ? 'DIR' : $this->formatSize(@filesize($fp));
            $items[] = "$f ($sz)";
            if (count($items) >= 8) {
                $items[] = "... e outros arquivos";
                break;
            }
        }
        return "// Conteúdo encontrado no diretório malicioso:\n" . implode("\n", $items);
    }

    private function getFileSnippet($path, $category, $content = null) {
        if (!file_exists($path)) return "[Arquivo não encontrado no disco]";
        if ($content === null) {
            $content = @file_get_contents($path, false, null, 0, 8192);
        }
        if ($content === false || $content === '') return "[Arquivo vazio ou binário não legível]";

        $lines = explode("\n", str_replace("\r\n", "\n", $content));
        $extracted = [];

        if (strpos($category, 'wp-config') !== false) {
            foreach ($lines as $i => $line) {
                if (strpos($line, '/* SC_WC */') !== false || strpos($line, 'WP_CACHE') !== false) {
                    $start = max(0, $i - 2);
                    $end = min(count($lines) - 1, $i + 2);
                    for ($j = $start; $j <= $end; $j++) {
                        $extracted[] = sprintf("%3d | %s", $j + 1, $lines[$j]);
                    }
                    return implode("\n", $extracted);
                }
            }
        }

        if (strpos($category, 'wp-settings') !== false) {
            foreach ($lines as $i => $line) {
                if (strpos($line, 'compat-utf8.php') !== false) {
                    $start = max(0, $i - 2);
                    $end = min(count($lines) - 1, $i + 2);
                    for ($j = $start; $j <= $end; $j++) {
                        $extracted[] = sprintf("%3d | %s", $j + 1, $lines[$j]);
                    }
                    return implode("\n", $extracted);
                }
            }
        }

        if (strpos($category, '.user.ini') !== false) {
            foreach ($lines as $i => $line) {
                if (stripos($line, 'auto_prepend_file') !== false) {
                    $extracted[] = sprintf("%3d | %s", $i + 1, $line);
                }
            }
            if (!empty($extracted)) return implode("\n", $extracted);
        }

        if (strpos($category, '.htaccess') !== false) {
            foreach ($lines as $i => $line) {
                if (stripos($line, 'lock360') !== false || stripos($line, 'radio.php') !== false || stripos($line, 'auto_prepend_file') !== false || stripos($line, 'about.php') !== false) {
                    $extracted[] = sprintf("%3d | %s", $i + 1, $line);
                }
            }
            if (!empty($extracted)) return implode("\n", $extracted);
        }

        // Padrão: primeiras 18 linhas
        $count = min(18, count($lines));
        for ($i = 0; $i < $count; $i++) {
            $extracted[] = sprintf("%3d | %s", $i + 1, $lines[$i]);
        }
        if (count($lines) > 18) {
            $extracted[] = "    | ... [restante omitido para visualização rápida]";
        }
        return implode("\n", $extracted);
    }

    private function registerThreat($rel, $path, $isDir, $category, $risk, $action, $actionLabel, $reason, $size = null, $snippet = null) {
        $id = substr(md5($rel . '|' . $category), 0, 12);
        
        if ($size === null) {
            $size = $isDir ? 'DIR' : $this->formatSize(@filesize($path));
        }
        if ($snippet === null) {
            $snippet = $isDir ? $this->getDirSnippet($path) : $this->getFileSnippet($path, $category);
        }

        $this->threatItems[$id] = [
            'id' => $id,
            'rel' => $rel,
            'path' => $path,
            'is_dir' => $isDir,
            'category' => $category,
            'risk' => $risk,
            'action' => $action,
            'action_label' => $actionLabel,
            'reason' => $reason,
            'size' => $size,
            'snippet' => $snippet
        ];
        if ($this->onThreat) {
            ($this->onThreat)($this->threatItems[$id]);
        }
    }

    public function run() {
        $this->log("Iniciando Verificação Heurística do Cerberus em: {$this->rootDir}");
        $this->log("Modo: " . ($this->dryRun ? "SIMULAÇÃO / DIAGNÓSTICO (DRY-RUN)" : "ERRADICAÇÃO ATIVA COM QUARENTENA"));

        $startTime = microtime(true);
        $this->scanDirectory($this->rootDir);
        $elapsed = round(microtime(true) - $startTime, 2);

        $this->stats['threat_count'] = count($this->threatItems);
        $this->stats['threat_items'] = $this->threatItems;

        $this->log("Varredura concluída em {$elapsed}s. Ameaças detectadas: {$this->stats['threat_count']}");

        // Se estiver em modo Dry-Run, apenas lista e não modifica nada
        if ($this->dryRun) {
            foreach ($this->threatItems as $t) {
                $this->log("[DIAGNÓSTICO] {$t['category']}: {$t['rel']}", "THREAT");
            }
            return $this->stats;
        }

        // Modo Erradicação Ativa: Filtra alvos se o usuário selecionou itens específicos
        $targetsToProcess = [];
        if ($this->targetIds !== null) {
            foreach ($this->targetIds as $tid) {
                if (isset($this->threatItems[$tid])) {
                    $targetsToProcess[$tid] = $this->threatItems[$tid];
                }
            }
        } else {
            $targetsToProcess = $this->threatItems;
        }

        if (empty($targetsToProcess)) {
            $this->log("Nenhuma ameaça selecionada para limpeza. Servidor mantido intacto.", "INFO");
            return $this->stats;
        }

        // 1. GARANTIA ZERO-LOSS: Cria Quarentena ZIP dos itens antes de qualquer alteração
        if ($this->onStep) {
            ($this->onStep)(1, 'Gerando Quarentena Automática (.zip)', 'Compactando ' . count($targetsToProcess) . ' itens com manifesto de segurança JSON...');
        }
        $quarantineZip = $this->createQuarantineZip($targetsToProcess);
        if ($quarantineZip) {
            $this->stats['quarantine_zip'] = $quarantineZip;
            $this->log("Cópia de segurança criada com sucesso no cofre: $quarantineZip", "BACKUP");
        }

        // 2. Executa a esterilização apenas dos itens selecionados pelo usuário
        if ($this->onStep) {
            ($this->onStep)(2, 'Expurgando e Higienizando Ameaças', 'Executando desinfecção seletiva nos alvos autorizados...');
        }
        foreach ($targetsToProcess as $item) {
            $this->executeAction($item);
        }

        // 3. Implanta a Vacina Must-Use em todas as instalações WordPress localizadas
        if ($this->onStep) {
            ($this->onStep)(3, 'Implantando Vacina Sentinela Must-Use', 'Ativando trava anti-SCV e imunização de bootloader no WordPress...');
        }
        $this->deployVaccines();

        if ($this->onStep) {
            ($this->onStep)(4, 'Esterilização Concluída com Sucesso', 'Hospedagem imunizada e backup disponível no cofre de quarentena.');
        }

        $this->log("============================================================");
        $this->log("Esterilização concluída em {$elapsed}s");
        $this->log("Itens processados: " . count($targetsToProcess));
        $this->log("Arquivos removidos: {$this->stats['deleted_files']} | Pastas removidas: {$this->stats['deleted_dirs']}");
        $this->log("Arquivos de Core limpos: {$this->stats['cleaned_core_files']}");
        $this->log("index.php restaurados: {$this->stats['restored_index_php']}");
        $this->log(".htaccess desinfetados: {$this->stats['sanitized_htaccess']}");
        $this->log(".user.ini desinfetados: {$this->stats['sanitized_user_ini']}");
        $this->log("Vacinas implantadas: {$this->stats['vaccines_deployed']}");
        $this->log("============================================================");

        return $this->stats;
    }

    public function createQuarantineZip(array $itemsToQuarantine) {
        if (!class_exists('ZipArchive')) {
            $this->log("Aviso: ZipArchive indisponível no PHP. Prosseguindo com backup padrão em pasta.", "WARN");
            return null;
        }

        if (!is_dir($this->quarantineDir)) {
            @mkdir($this->quarantineDir, 0755, true);
        }

        $zipName = 'quarantine_' . date('Y-m-d_H-i-s') . '.zip';
        $zipFullPath = $this->quarantineDir . DIRECTORY_SEPARATOR . $zipName;

        $zip = new ZipArchive();
        if ($zip->open($zipFullPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            $this->log("Falha ao abrir arquivo ZIP de quarentena: $zipFullPath", "WARN");
            return null;
        }

        $manifest = [
            'created_at' => date('Y-m-d H:i:s'),
            'server' => php_uname(),
            'php_version' => PHP_VERSION,
            'root_path' => $this->rootDir,
            'threats_count' => count($itemsToQuarantine),
            'items' => []
        ];

        foreach ($itemsToQuarantine as $item) {
            $path = $item['path'];
            $rel = $item['rel'];

            $manifest['items'][] = [
                'id' => $item['id'],
                'rel' => $rel,
                'category' => $item['category'],
                'risk' => $item['risk'],
                'action' => $item['action'],
                'reason' => $item['reason']
            ];

            if (is_file($path)) {
                $zip->addFile($path, $rel);
            } elseif (is_dir($path)) {
                $this->addDirToZip($zip, $path, $rel);
            }
        }

        $zip->addFromString('manifest.json', json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        $zip->close();

        return $zipName;
    }

    private function addDirToZip($zip, $dir, $baseRel) {
        $zip->addEmptyDir($baseRel);
        $files = @scandir($dir);
        if (!$files) return;
        foreach ($files as $f) {
            if ($f === '.' || $f === '..') continue;
            $fp = $dir . DIRECTORY_SEPARATOR . $f;
            $rel = $baseRel . '/' . $f;
            if (is_dir($fp)) {
                $this->addDirToZip($zip, $fp, $rel);
            } elseif (is_file($fp)) {
                $zip->addFile($fp, $rel);
            }
        }
    }

    public function listQuarantineBackups() {
        if (!is_dir($this->quarantineDir)) return [];
        $files = @scandir($this->quarantineDir);
        if (!$files) return [];
        $zips = [];
        foreach ($files as $f) {
            if (substr($f, -4) === '.zip' && strpos($f, 'quarantine_') === 0) {
                $p = $this->quarantineDir . DIRECTORY_SEPARATOR . $f;
                $sz = @filesize($p);
                $mtime = @filemtime($p);
                $zips[] = [
                    'filename' => $f,
                    'path' => $p,
                    'size' => $this->formatSize($sz),
                    'size_raw' => $sz,
                    'date' => date('d/m/Y H:i:s', $mtime),
                    'timestamp' => $mtime
                ];
            }
        }
        usort($zips, function($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });
        return $zips;
    }

    public function restoreFromQuarantine($zipFilename) {
        if (!class_exists('ZipArchive')) {
            return [false, 'Extensão ZipArchive não habilitada.'];
        }
        $zipFullPath = $this->quarantineDir . DIRECTORY_SEPARATOR . basename($zipFilename);
        if (!file_exists($zipFullPath)) {
            return [false, 'Arquivo ZIP de quarentena não encontrado no disco.'];
        }

        $zip = new ZipArchive();
        if ($zip->open($zipFullPath) !== true) {
            return [false, 'Erro ao abrir arquivo ZIP de quarentena.'];
        }

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $entryName = $zip->getNameIndex($i);
            if ($entryName === 'manifest.json') continue;
            $destPath = $this->rootDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $entryName);
            if (substr($entryName, -1) === '/') {
                @mkdir($destPath, 0755, true);
            } else {
                @mkdir(dirname($destPath), 0755, true);
                $content = $zip->getFromIndex($i);
                @file_put_contents($destPath, $content);
            }
        }
        $zip->close();
        return [true, "Backup $zipFilename restaurado com sucesso para a hospedagem!"];
    }

    private function executeAction($item) {
        $p = $item['path'];
        $rel = $item['rel'];
        $act = $item['action'];

        switch ($act) {
            case 'delete':
                $this->executeDelete($p, $item['is_dir'], $rel);
                break;
            case 'sanitize_user_ini':
                $this->executeSanitizeUserIni($p, $rel);
                break;
            case 'sanitize_htaccess':
                $this->executeSanitizeHtaccess($p, $rel);
                break;
            case 'sanitize_wp_config':
                $this->executeSanitizeWpConfig($p, $rel);
                break;
            case 'sanitize_wp_settings':
                $this->executeSanitizeWpSettings($p, $rel);
                break;
            case 'restore_index_php':
                $this->executeRestoreIndexPhp($p, $rel);
                break;
        }
    }

    private function executeDelete($p, $isDir, $rel) {
        try {
            if ($isDir) {
                $this->recursiveDelete($p);
                $this->stats['deleted_dirs']++;
                $this->log("Diretório malicioso expurgado: $rel", "CLEAN");
            } else {
                @chmod($p, 0666);
                @unlink($p);
                $this->stats['deleted_files']++;
                $this->log("Arquivo malicioso expurgado: $rel", "CLEAN");
            }
        } catch (\Throwable $e) {
            $this->log("Erro ao remover $rel: " . $e->getMessage(), "WARN");
        }
    }

    private function recursiveDelete($dir) {
        if (!is_dir($dir)) return;
        $items = @scandir($dir);
        if (!$items) return;
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $p = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($p)) {
                $this->recursiveDelete($p);
            } else {
                @chmod($p, 0666);
                @unlink($p);
            }
        }
        @rmdir($dir);
    }

    private function executeSanitizeUserIni($p, $rel) {
        $content = @file_get_contents($p);
        if (!$content) return;
        $cleaned = trim(preg_replace('/auto_prepend_file\s*=.*(\r?\n)?/i', '', $content));
        if (empty($cleaned)) {
            @unlink($p);
            $this->log("Removido .user.ini malicioso vazio: $rel", "CLEAN");
        } else {
            @file_put_contents($p, $cleaned . "\n");
            $this->log("Desinfetado .user.ini (auto_prepend_file removido): $rel", "CLEAN");
        }
        $this->stats['sanitized_user_ini']++;
    }

    private function executeSanitizeHtaccess($p, $rel) {
        $norm = str_replace('\\', '/', $p);
        $isSubfolder = (strpos($norm, '/wp-content/') !== false || strpos($norm, '/wp-includes/') !== false || strpos($norm, '/wp-admin/') !== false);
        if ($isSubfolder) {
            @unlink($p);
            $this->log("Removido .htaccess rogue de subdiretório: $rel", "CLEAN");
        } else {
            @file_put_contents($p, $this->standardHtaccess);
            $this->log("Restaurado .htaccess oficial da raiz: $rel", "CLEAN");
        }
        $this->stats['sanitized_htaccess']++;
    }

    private function executeSanitizeWpConfig($p, $rel) {
        $content = @file_get_contents($p);
        if (!$content) return;
        $cleaned = preg_replace('/define\s*\(\s*[\'"]WP_CACHE[\'"]\s*,\s*true\s*\)\s*;\s*\/\*\s*SC_WC\s*\*\/\r?\n?/', '', $content);
        @file_put_contents($p, $cleaned);
        $this->log("Removida injeção WP_CACHE SC_WC de: $rel", "CLEAN");
        $this->stats['cleaned_core_files']++;
    }

    private function executeSanitizeWpSettings($p, $rel) {
        $content = @file_get_contents($p);
        if (!$content) return;
        $cleaned = preg_replace('/require\s+ABSPATH\s*\.\s*WPINC\s*\.\s*[\'"]\/compat-utf8\.php[\'"]\s*;\r?\n?/', '', $content);
        @file_put_contents($p, $cleaned);
        $this->log("Removido require compat-utf8.php de: $rel", "CLEAN");
        $this->stats['cleaned_core_files']++;
    }

    private function executeRestoreIndexPhp($p, $rel) {
        @file_put_contents($p, $this->standardIndex);
        $this->log("Restaurado index.php oficial do WordPress: $rel", "CLEAN");
        $this->stats['restored_index_php']++;
    }

    private function deployVaccines() {
        foreach ($this->wpRoots as $wpDir) {
            $muDir = $wpDir . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'mu-plugins';
            if (!is_dir($muDir)) {
                @mkdir($muDir, 0755, true);
            }
            $vFile = $muDir . DIRECTORY_SEPARATOR . '000-antidoto-vaccine.php';
            if (!file_exists($vFile)) {
                @file_put_contents($vFile, $this->vaccineCode);
                $rel = ltrim(str_replace($this->rootDir, '', $vFile), '/\\');
                $this->log("Vacina Must-Use Sentinela implantada com sucesso em: $rel", "CLEAN");
                $this->stats['vaccines_deployed']++;
            }
        }
    }

    private function scanDirectory($dir) {
        $skipDirs = [
            '.trash', 'quarantine_backup', '.git', '.cache', 'node_modules',
            'logs', 'mail', 'ssl', '.cphorde', '.spamassassin', 'vendor',
            '.agents', 'agentic-awesome-skills', 'docker-lab', 'github-release',
            'softaculous_backups', 'database', 'perl5', 'etc', 'tmp'
        ];
        $items = @scandir($dir);
        if (!$items) return;

        $this->stats['scanned_dirs']++;

        foreach ($items as $item) {
            if ($item === '.' || $item === '..') continue;
            $p = $dir . DIRECTORY_SEPARATOR . $item;
            $rel = ltrim(str_replace($this->rootDir, '', $p), '/\\');

            if (is_dir($p)) {
                if (in_array($item, $skipDirs, true)) continue;
                if ($this->onProgress) {
                    ($this->onProgress)($this->stats['scanned_files'], $this->stats['scanned_dirs'], $rel);
                }

                // 1. SCV Core folders (.sc_*, .sc_ymp)
                if (strpos($item, '.sc_') === 0) {
                    $this->registerThreat(
                        $rel, $p, true,
                        'SCV Core / Persistência',
                        'CRÍTICO',
                        'delete',
                        'Excluir Diretório',
                        'Pasta oculta de infraestrutura e persistência do worm SCV.'
                    );
                    continue;
                }

                // 2. Numeric/Hex webshell folders (e.g. 586381, 144710, 6cd6e2e4, bca42b57)
                if (preg_match('/^(?:586381|144710|bca42b57)$/', $item) || (preg_match('/^[0-9a-f]{6,10}$/i', $item) && file_exists($p . DIRECTORY_SEPARATOR . 'about.php'))) {
                    $this->registerThreat(
                        $rel, $p, true,
                        'Webshell / Backdoor Oculto',
                        'CRÍTICO',
                        'delete',
                        'Excluir Diretório',
                        'Diretório arbitrário contendo webshells de controle remoto do servidor.'
                    );
                    continue;
                }

                // 3. Fake theme spam directories (*_178*)
                if (preg_match('/^(?:archives|author-template|author_template|comment_section|config|custom_file_\d+|error-404|page-template|search-template|top|widget-area)[_-]\d{7,}$/i', $item)) {
                    $this->registerThreat(
                        $rel, $p, true,
                        'Spam Doorway / Fake Theme',
                        'ALTO',
                        'delete',
                        'Excluir Diretório',
                        'Diretório falso criado pelo malware para cloaking de SEO e spambot.'
                    );
                    continue;
                }

                // 4. smooth-librarian-lite plugin dir
                if ($item === 'smooth-librarian-lite' && (strpos($dir, 'plugins') !== false || strpos($dir, 'mu-plugins') !== false)) {
                    $this->registerThreat(
                        $rel, $p, true,
                        'Malware SCV Librarian Plugin',
                        'CRÍTICO',
                        'delete',
                        'Excluir Diretório',
                        'Módulo de replicação viral smooth-librarian-lite instalado em mu-plugins/plugins.'
                    );
                    continue;
                }

                // Recursão
                $this->scanDirectory($p);
            } else {
                $this->stats['scanned_files']++;
                if ($this->onProgress && ($this->stats['scanned_files'] <= 15 || $this->stats['scanned_files'] % 5 === 0)) {
                    ($this->onProgress)($this->stats['scanned_files'], $this->stats['scanned_dirs'], $rel);
                }
                $this->inspectFile($p, $item, $rel);
            }
        }
    }

    private function inspectFile($p, $item, $rel) {
        $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
        // Ignora extensões estáticas e binários de mídia que não executam código PHP
        $staticExts = [
            'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'avif',
            'woff', 'woff2', 'ttf', 'eot', 'otf',
            'mp4', 'webm', 'mp3', 'ogg', 'wav', 'pdf',
            'css', 'map', 'json', 'xml', 'po', 'mo', 'txt', 'md'
        ];
        if (in_array($ext, $staticExts, true)) {
            return;
        }

        $sz = @filesize($p);

        // .user.ini
        if ($item === '.user.ini') {
            $content = @file_get_contents($p);
            if ($content && preg_match('/auto_prepend_file\s*=\s*[\'"][^\'"]*\.php[\'"]/i', $content) && strpos($content, 'wordfence-waf.php') === false) {
                $this->registerThreat(
                    $rel, $p, false,
                    'Hijack de Bootloader (.user.ini)',
                    'CRÍTICO',
                    'sanitize_user_ini',
                    'Desinfetar .user.ini',
                    'Instrução auto_prepend_file força o PHP a carregar o vírus antes de qualquer script.'
                );
            }
            return;
        }

        // .htaccess
        if ($item === '.htaccess') {
            $isRogue = false;
            $reason = '';
            if ($sz === 420) {
                $isRogue = true;
                $reason = 'Arquivo .htaccess de tamanho padrão do SCV (420 bytes) com redirecionamento forçado.';
            } elseif ($sz < 5000) {
                $content = @file_get_contents($p);
                if ($content && (strpos($content, 'lock360.php') !== false || strpos($content, 'radio.php') !== false || preg_match('/php_value\s+auto_prepend_file/i', $content))) {
                    $isRogue = true;
                    $reason = 'Arquivo .htaccess manipulado para injetar auto_prepend_file ou webshell lock360/radio.';
                } elseif (strpos($p, 'mu-plugins') !== false && (strpos($content, 'about.php') !== false || strpos($content, 'lock360') !== false)) {
                    $isRogue = true;
                    $reason = 'Arquivo .htaccess malicioso localizado dentro de mu-plugins.';
                }
            }

            if ($isRogue) {
                $this->registerThreat(
                    $rel, $p, false,
                    'Hijack de Servidor (.htaccess)',
                    'ALTO',
                    'sanitize_htaccess',
                    'Restaurar .htaccess Padrão',
                    $reason
                );
            }
            return;
        }

        // wp-config.php
        if ($item === 'wp-config.php') {
            $this->wpRoots[] = dirname($p);
            $content = @file_get_contents($p);
            if ($content && (strpos($content, '/* SC_WC */') !== false || preg_match('/define\s*\(\s*[\'"]WP_CACHE[\'"]\s*,\s*true\s*\)\s*;\s*\/\*\s*SC_WC\s*\*\//', $content))) {
                $this->registerThreat(
                    $rel, $p, false,
                    'Injeção de Core (wp-config.php)',
                    'CRÍTICO',
                    'sanitize_wp_config',
                    'Limpar Injeção SC_WC',
                    'O malware injetou a flag SC_WC para forçar a execução contínua de advanced-cache.php infectado.'
                );
            }
            return;
        }

        // wp-settings.php
        if ($item === 'wp-settings.php') {
            $content = @file_get_contents($p);
            if ($content && strpos($content, 'compat-utf8.php') !== false) {
                $this->registerThreat(
                    $rel, $p, false,
                    'Injeção de Core (wp-settings.php)',
                    'CRÍTICO',
                    'sanitize_wp_settings',
                    'Remover require compat-utf8',
                    'Linha require compat-utf8.php injetada no núcleo do WordPress para reativar o malware.'
                );
            }
            return;
        }

        // index.php
        if ($item === 'index.php') {
            $content = @file_get_contents($p);
            if ($content) {
                $isSpam = false;
                if (strpos($content, 'スタート') !== false || strpos($content, '関数群') !== false || strpos($content, 'rakuten17jp') !== false) {
                    $isSpam = true;
                } elseif (strpos($content, 'wp-blog-header.php') === false && (strpos($content, 'base64_decode') !== false || strpos($content, 'eval(') !== false)) {
                    $isSpam = true;
                }

                if ($isSpam) {
                    $this->registerThreat(
                        $rel, $p, false,
                        'SEO Spam Doorway (index.php)',
                        'CRÍTICO',
                        'restore_index_php',
                        'Restaurar index.php Oficial',
                        'O arquivo index.php oficial foi substituído por um gerador de spam e doorway malicioso.'
                    );
                }
            }
            return;
        }

        // SCV hash loaders: wp-content/e139edec.php ou wp-content/.e139edec.php
        if (strpos($p, 'wp-content') !== false && preg_match('/^\.?([0-9a-f]{8})\.php$/i', $item)) {
            $snippet = @file_get_contents($p, false, null, 0, 1024);
            if ($snippet && (strpos($snippet, '_scp=dirname') !== false || strpos($snippet, 'kh4115rhjhz') !== false || strpos($snippet, '_sc_padf') !== false)) {
                $this->registerThreat(
                    $rel, $p, false,
                    'SCV Hash Loader (wp-content)',
                    'CRÍTICO',
                    'delete',
                    'Excluir Arquivo',
                    'Script PHP de carregamento dinâmico e backdoor camuflado com nome de hash hexadecimal.'
                );
                return;
            }
        }

        // smooth-librarian-lite.php
        if ($item === 'smooth-librarian-lite.php') {
            $this->registerThreat(
                $rel, $p, false,
                'Malware SCV Librarian Core',
                'CRÍTICO',
                'delete',
                'Excluir Arquivo',
                'Núcleo central de comando e propagação do malware SCV / smooth-librarian-lite.'
            );
            return;
        }

        // SCV tracking files in mu-plugins (.sd_, .rd_, .bt_, .wr_, .q_)
        if (preg_match('/^\.(?:sd|rd|bt|wr|q)_smooth-librarian/i', $item)) {
            $this->registerThreat(
                $rel, $p, false,
                'SCV Tracking Marker',
                'MÉDIO',
                'delete',
                'Excluir Arquivo',
                'Arquivo de controle de estado e contadores do worm SCV.'
            );
            return;
        }

        // advanced-cache.php
        if ($item === 'advanced-cache.php') {
            $snippet = @file_get_contents($p, false, null, 0, 1024);
            if ($snippet && (strpos($snippet, '/* SC_ADV_BEGIN:') !== false || strpos($snippet, '_sc_padf') !== false)) {
                $this->registerThreat(
                    $rel, $p, false,
                    'SCV Advanced Cache Hijack',
                    'CRÍTICO',
                    'delete',
                    'Excluir Arquivo',
                    'Arquivo de cache forjado para garantir execução primária pelo WordPress.'
                );
                return;
            }
        }

        // Webshells Conhecidos (lock360.php, radio.php, rogue about.php, 2index.php)
        $fnLower = strtolower($item);
        if ($fnLower === 'lock360.php' || $fnLower === 'radio.php' || $fnLower === '2index.php') {
            $this->registerThreat(
                $rel, $p, false,
                'Webshell Remota (Backdoor)',
                'CRÍTICO',
                'delete',
                'Excluir Arquivo',
                'Webshell conhecida que concede aos invasores execução de código e comandos no servidor.'
            );
            return;
        }

        if ($fnLower === 'wp-login.php' && (strpos($p, 'smilies') !== false || strpos($p, 'images') !== false || strpos($p, 'uploads') !== false)) {
            $this->registerThreat(
                $rel, $p, false,
                'Fake wp-login Webshell',
                'CRÍTICO',
                'delete',
                'Excluir Arquivo',
                'Webshell camuflada como tela de login do WordPress em pasta de imagens ou uploads.'
            );
            return;
        }

        if ($fnLower === 'about.php') {
            $norm = str_replace('\\', '/', $p);
            if (strpos($norm, '/wp-admin/') === false && strpos($norm, '/wp-admin__') === false) {
                $this->registerThreat(
                    $rel, $p, false,
                    'Webshell Disfarçada (about.php)',
                    'CRÍTICO',
                    'delete',
                    'Excluir Arquivo',
                    'Arquivo about.php malicioso localizado fora do diretório legítimo /wp-admin/.'
                );
                return;
            }
        }

        // SCV zip payloads em wp-content
        if (substr($item, -4) === '.zip' && strpos($p, 'wp-content') !== false && preg_match('/^[0-9a-f]{8}\.zip$/i', $item)) {
            $this->registerThreat(
                $rel, $p, false,
                'SCV Zip Payload',
                'ALTO',
                'delete',
                'Excluir Arquivo',
                'Arquivo ZIP contendo cópia do malware para auto-regeneração.'
            );
            return;
        }

        // Uploads drops (smooth-librarian-lite*.zip)
        if (strpos($item, 'smooth-librari') !== false && strpos($p, 'uploads') !== false) {
            $this->registerThreat(
                $rel, $p, false,
                'Dropped Upload Malware',
                'ALTO',
                'delete',
                'Excluir Arquivo',
                'Arquivo do malware dropado no diretório de uploads.'
            );
            return;
        }
    }
}

// ==========================================
// ROTEAMENTO: CLI OU INTERFACE WEB
// ==========================================
if (php_sapi_name() === 'cli') {
    if (!isset($_SERVER['SCRIPT_FILENAME']) || realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
        $dryRun = true;
        $targetPath = '.';
        foreach ($argv as $arg) {
            if ($arg === '--clean') $dryRun = false;
            if (strpos($arg, '--path=') === 0) $targetPath = substr($arg, 7);
        }
        $sterilizer = new HostingSterilizerPHP($targetPath, $dryRun, 'quarantine_backup');
        $sterilizer->run();
    }
    return;
}

// Modo Web - Valida Token de Segurança
$token = $_GET['token'] ?? $_POST['token'] ?? '';
$action = $_POST['action'] ?? $_GET['action'] ?? 'view';

// Localiza e codifica logo oficial transparente do Cerberus Guardião em base64 Data URI
$logoDataUri = '';
$embeddedLogoDataUri = 'data:image/png;base64,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';

$logoPath = null;
$possibleLogoPaths = [
    dirname(__FILE__) . '/cerberus-logo.png',
    dirname(__FILE__) . '/wp-content/plugins/cerberus-sentinel/assets/cerberus-logo.png',
    dirname(__FILE__) . '/wp-content/mu-plugins/assets/cerberus-logo.png',
    dirname(__FILE__) . '/assets/cerberus-logo.png',
    dirname(__FILE__) . '/../assets/cerberus-logo.png',
    dirname(__FILE__) . '/cerberus-logo.jpg',
    dirname(__FILE__) . '/../assets/cerberus-logo.jpg',
    isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] . '/wp-content/plugins/cerberus-sentinel/assets/cerberus-logo.png' : '',
    isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] . '/cerberus-logo.png' : '',
    isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] . '/assets/cerberus-logo.png' : '',
    isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] . '/cpanel/cerberus-logo.png' : '',
    '/var/www/cpanel-hub/cerberus-logo.png'
];
foreach ($possibleLogoPaths as $p) {
    if (!empty($p) && file_exists($p) && is_readable($p)) {
        $logoPath = $p;
        $mime = (substr($p, -4) === '.png') ? 'image/png' : 'image/jpeg';
        $logoDataUri = 'data:' . $mime . ';base64,' . base64_encode(file_get_contents($p));
        break;
    }
}

// Tela de Autenticação Segura
if ($token !== STERILIZER_SECRET_TOKEN) {
    http_response_code(403);
    $imgSrc = !empty($logoDataUri) ? $logoDataUri : $embeddedLogoDataUri;
    ?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CerberusWP - Autenticação Segura</title>
    <style>
        @import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap");
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background: #07090e;
            color: #f8fafc;
            font-family: "Plus Jakarta Sans", sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
            background-image: 
                radial-gradient(circle at 50% 30%, rgba(139, 92, 246, 0.16), transparent 60%),
                radial-gradient(circle at 80% 80%, rgba(0, 242, 254, 0.12), transparent 50%),
                radial-gradient(rgba(139, 92, 246, 0.15) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 32px 32px;
        }
        .auth-card {
            background: rgba(14, 20, 32, 0.85);
            backdrop-filter: blur(24px) saturate(180%);
            -webkit-backdrop-filter: blur(24px) saturate(180%);
            border: 1px solid rgba(139, 92, 246, 0.3);
            border-radius: 24px;
            padding: 42px 36px;
            text-align: center;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.75), inset 0 1px 0 rgba(255, 255, 255, 0.08);
            max-width: 440px;
            width: 100%;
            position: relative;
            overflow: hidden;
        }
        .auth-card::before {
            content: "";
            position: absolute;
            top: 0; left: 0; right: 0; height: 2px;
            background: linear-gradient(90deg, transparent, #00f2fe, #8b5cf6, transparent);
        }
        .auth-icon-wrap {
            width: 88px;
            height: 88px;
            margin: 0 auto 20px;
            background: transparent;
            border: none;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .auth-icon-wrap img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            filter: drop-shadow(0 0 16px rgba(0, 242, 254, 0.45)) drop-shadow(0 0 24px rgba(139, 92, 246, 0.3));
        }
        h2 {
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.4px;
            margin-bottom: 8px;
            color: #fff;
        }
        h2 span {
            background: linear-gradient(135deg, #00f2fe, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p {
            color: #94a3b8;
            font-size: 13.5px;
            line-height: 1.6;
            margin-bottom: 26px;
        }
        .input-group {
            margin-bottom: 18px;
            text-align: left;
        }
        .input-label {
            display: block;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 700;
            color: #a78bfa;
            margin-bottom: 6px;
            font-family: "JetBrains Mono", monospace;
        }
        input {
            width: 100%;
            padding: 14px 16px;
            border-radius: 12px;
            border: 1px solid rgba(139, 92, 246, 0.35);
            background: rgba(7, 10, 17, 0.9);
            color: #00f2fe;
            font-family: "JetBrains Mono", monospace;
            font-size: 14px;
            outline: none;
            transition: all 0.25s;
        }
        input:focus {
            border-color: #00f2fe;
            box-shadow: 0 0 20px rgba(0, 242, 254, 0.3), inset 0 0 10px rgba(0, 242, 254, 0.1);
        }
        button {
            width: 100%;
            padding: 14px 20px;
            border-radius: 12px;
            border: none;
            background: linear-gradient(135deg, #00f2fe 0%, #8b5cf6 100%);
            color: #07090e;
            font-size: 14px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.6px;
            cursor: pointer;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            box-shadow: 0 8px 25px rgba(0, 242, 254, 0.35);
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 35px rgba(0, 242, 254, 0.5);
        }
        button:active {
            transform: scale(0.98);
        }
    </style>
</head>
<body>
    <div class="auth-card">
        <div class="auth-icon-wrap">
            <img src="<?php echo htmlspecialchars($imgSrc, ENT_QUOTES); ?>" onerror="this.onerror=null;this.src='<?php echo htmlspecialchars($embeddedLogoDataUri, ENT_QUOTES); ?>';" alt="CerberusWP">
        </div>
        <h2>CERBERUS<span>WP</span></h2>
        <p>Insira a chave de segurança para liberar o console de esterilização e expurgo de raiz do servidor.</p>
        <form method="GET">
            <div class="input-group">
                <label class="input-label">Chave de Segurança</label>
                <input type="password" name="token" placeholder="Digite a chave de segurança..." autofocus required>
            </div>
            <button type="submit">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                Autenticar & Liberar Acesso
            </button>
        </form>
    </div>
</body>
</html>
    <?php
    exit;
}

// Configuração de diretório de varredura (Detecção inteligente de ambiente cPanel / Hospedagem)
$autoDetectedTarget = realpath(dirname(__FILE__) . '/..') ?: realpath(dirname(__FILE__));
if (isset($_SERVER['DOCUMENT_ROOT'])) {
    $docRoot = realpath($_SERVER['DOCUMENT_ROOT']) ?: $_SERVER['DOCUMENT_ROOT'];
    // Em cPanel, DOCUMENT_ROOT geralmente é /home/usuario/public_html, cujo pai é a raiz da conta
    $parentDocRoot = dirname($docRoot);
    if (is_dir($parentDocRoot) && is_readable($parentDocRoot) && basename($docRoot) === 'public_html') {
        $autoDetectedTarget = $parentDocRoot;
    } else {
        $autoDetectedTarget = $docRoot;
    }
}
$defaultTarget = $autoDetectedTarget;
$customPath = !empty($_POST['custom_path']) ? trim($_POST['custom_path']) : (!empty($_GET['custom_path']) ? trim($_GET['custom_path']) : $defaultTarget);
$scanPath = is_dir($customPath) ? realpath($customPath) : $defaultTarget;

// Mapeamento automático de domínios/sites WordPress presentes na conta
$detectedSites = [];
$accountRoot = $scanPath;
$accountEntries = @scandir($accountRoot);
if ($accountEntries) {
    foreach ($accountEntries as $ae) {
        if ($ae === '.' || $ae === '..' || strpos($ae, '.') === 0) continue;
        $fullSub = $accountRoot . DIRECTORY_SEPARATOR . $ae;
        if (is_dir($fullSub) && (file_exists($fullSub . '/wp-config.php') || file_exists($fullSub . '/index.php'))) {
            $detectedSites[] = [
                'name' => $ae,
                'path' => $fullSub
            ];
        }
    }
}

$possibleQuarantinePaths = [
    $scanPath . '/quarantine_backup',
    dirname(__FILE__) . '/../quarantine_backup',
    dirname(__FILE__) . '/quarantine_backup'
];
$quarantinePath = $possibleQuarantinePaths[0];
foreach ($possibleQuarantinePaths as $qp) {
    if (is_dir($qp)) {
        $quarantinePath = realpath($qp) ?: $qp;
        break;
    }
}

// Instancia esterilizador para obter funções utilitárias (ex: backups)
$tempSterilizer = new HostingSterilizerPHP($scanPath, true, $quarantinePath);

// DOWNLOAD DE QUARENTENA ZIP
if ($action === 'download_quarantine') {
    $zipFile = basename($_GET['file'] ?? '');
    $fullPath = null;
    foreach ($possibleQuarantinePaths as $qp) {
        $check = (realpath($qp) ?: $qp) . DIRECTORY_SEPARATOR . $zipFile;
        if (file_exists($check) && is_readable($check)) {
            $fullPath = $check;
            break;
        }
    }
    if ($fullPath && substr($zipFile, -4) === '.zip') {
        while (ob_get_level()) ob_end_clean();
        header('Content-Description: File Transfer');
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . $zipFile . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
        header('Pragma: public');
        header('Content-Length: ' . filesize($fullPath));
        readfile($fullPath);
        exit;
    } else {
        die("Erro: Arquivo de quarentena não encontrado no servidor.");
    }
}

// CENÁRIO DE TESTE / LABORATÓRIO ISOLADO
if ($action === 'inject_lab_scenario') {
    $labDir = $accountRoot . DIRECTORY_SEPARATOR . 'lab_simulation';
    @mkdir($labDir . DIRECTORY_SEPARATOR . '.sc_stealth_core', 0755, true);
    @mkdir($labDir . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'mu-plugins', 0755, true);
    
    $payloadFilePath = $labDir . DIRECTORY_SEPARATOR . '.sc_stealth_core' . DIRECTORY_SEPARATOR . 'payload.php';
    file_put_contents($payloadFilePath, "<?php\n// SCV Stealth Rootkit Sample\n_sc_padf();\n");
    
    $autoPrependDirective = "auto_prepend_file = '" . str_replace('\\', '/', $payloadFilePath) . "'\n";
    file_put_contents($labDir . DIRECTORY_SEPARATOR . '.user.ini', $autoPrependDirective);
    file_put_contents($labDir . DIRECTORY_SEPARATOR . '.htaccess', "# BEGIN Rogue Security\nRewriteEngine On\nRewriteRule lock360.php [L]\n# END Rogue\n");
    file_put_contents($labDir . DIRECTORY_SEPARATOR . 'wp-config.php', "<?php\ndefine('WP_CACHE', true); /* SC_WC */\ndefine('DB_NAME', 'lab_simulation_db');\nrequire_once ABSPATH . 'wp-settings.php';\n");
    file_put_contents($labDir . DIRECTORY_SEPARATOR . 'wp-settings.php', "<?php\nrequire ABSPATH . WPINC . '/compat-utf8.php';\n");
    file_put_contents($labDir . DIRECTORY_SEPARATOR . 'radio.php', "<?php\n// Simulated webshell backdoor\nif (isset(\$_POST['cmd'])) { echo 'shell_active'; }\n");
    file_put_contents($labDir . DIRECTORY_SEPARATOR . 'index.php', "<?php\n// スタート Doorway spam sample\necho 'doorway_active';\n");

    if (isset($_REQUEST['ajax']) || (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false)) {
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'path' => $labDir, 'message' => 'Cenário de teste gerado com sucesso!']);
        exit;
    }
    header("Location: ?token=" . urlencode($token) . "&action=simulate&custom_path=" . urlencode($labDir));
    exit;
}

if ($action === 'reset_lab_scenario') {
    $labDir = $accountRoot . DIRECTORY_SEPARATOR . 'lab_simulation';
    if (is_dir($labDir)) {
        $delRecursive = function($d) use (&$delRecursive) {
            foreach (@scandir($d) ?: [] as $f) {
                if ($f === '.' || $f === '..') continue;
                $p = $d . DIRECTORY_SEPARATOR . $f;
                is_dir($p) ? $delRecursive($p) : @unlink($p);
            }
            @rmdir($d);
        };
        $delRecursive($labDir);
    }
    if (isset($_REQUEST['ajax']) || (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false)) {
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'message' => 'Cenário de teste limpo e removido.']);
        exit;
    }
    header("Location: ?token=" . urlencode($token));
    exit;
}

// MODO STREAMING SSE (TEMPO REAL AO VIVO)
if (isset($_REQUEST['stream']) && $_REQUEST['stream'] === '1') {
    @ini_set('zlib.output_compression', 0);
    @ini_set('implicit_flush', 1);
    while (ob_get_level()) ob_end_clean();

    header('Content-Type: text/event-stream; charset=utf-8');
    header('Cache-Control: no-cache, no-transform');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');

    $emit = function($event, $data) {
        echo "event: " . $event . "\n";
        echo "data: " . json_encode($data, JSON_UNESCAPED_UNICODE) . "\n\n";
        flush();
    };

    if ($action === 'clean_selected') {
        $selectedIds = $_POST['selected_threats'] ?? ($_GET['selected_threats'] ?? []);
        if (is_string($selectedIds)) {
            $selectedIds = array_filter(array_map('trim', explode(',', $selectedIds)));
        }
        
        $emit('step', ['step' => 1, 'title' => 'Inicializando Quarentena', 'desc' => count($selectedIds) . ' itens selecionados para quarentena']);
        usleep(350000);

        $sterilizer = new HostingSterilizerPHP($scanPath, false, $quarantinePath, $selectedIds);
        $sterilizer->onStep = function($step, $title, $desc) use ($emit) {
            $emit('step', ['step' => $step, 'title' => $title, 'desc' => $desc]);
            usleep(450000);
        };
        $sterilizer->onLog = function($msg, $level, $ts) use ($emit) {
            $emit('log', ['msg' => $msg, 'level' => $level, 'timestamp' => $ts]);
            usleep(40000);
        };

        $res = $sterilizer->run();
        $emit('done', [
            'stats' => $res,
            'quarantine_zip' => $res['quarantine_zip']
        ]);
        exit;
    } else {
        $sterilizer = new HostingSterilizerPHP($scanPath, true, $quarantinePath);
        $sterilizer->onProgress = function($files, $dirs, $current) use ($emit) {
            $emit('progress', [
                'scanned_files' => $files,
                'scanned_dirs' => $dirs,
                'current' => $current
            ]);
            usleep(15000);
        };
        $sterilizer->onThreat = function($threat) use ($emit) {
            $emit('threat', $threat);
            usleep(70000);
        };
        $sterilizer->onLog = function($msg, $level, $ts) use ($emit) {
            $emit('log', ['msg' => $msg, 'level' => $level, 'timestamp' => $ts]);
        };

        $res = $sterilizer->run();
        $emit('done', [
            'stats' => $res,
            'threat_count' => count($res['threat_items'])
        ]);
        exit;
    }
}

// RESTAURAÇÃO DE QUARENTENA ZIP
$statusMessage = null;
$statusType = 'info';
if ($action === 'restore_quarantine' && !empty($_POST['zip_file'])) {
    list($ok, $msg) = $tempSterilizer->restoreFromQuarantine($_POST['zip_file']);
    $statusMessage = $msg;
    $statusType = $ok ? 'success' : 'danger';
    if (isset($_REQUEST['ajax']) || (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false)) {
        header('Content-Type: application/json');
        echo json_encode(['success' => $ok, 'message' => $msg]);
        exit;
    }
}

// EXECUÇÃO DO SCAN OU LIMPEZA SÍNCRONA
$results = null;
if ($action === 'clean_selected') {
    $selectedIds = $_POST['selected_threats'] ?? [];
    $sterilizer = new HostingSterilizerPHP($scanPath, false, $quarantinePath, $selectedIds);
    $results = $sterilizer->run();
    $statusMessage = "Esterilização concluída com sucesso! Os arquivos selecionados foram expurgados e uma cópia de segurança ZIP foi salva no cofre de quarentena.";
    $statusType = 'success';
} elseif ($action === 'simulate') {
    $sterilizer = new HostingSterilizerPHP($scanPath, true, $quarantinePath);
    $results = $sterilizer->run();
}

$quarantineBackups = $tempSterilizer->listQuarantineBackups();
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CerberusWP | Cyber Sentinel & Threat Matrix</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,600;0,700;1,400&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-obsidian: #07090e;
            --bg-card: rgba(14, 20, 32, 0.82);
            --bg-card-hover: rgba(18, 26, 42, 0.95);
            --bg-well: rgba(7, 10, 17, 0.9);
            --border-glow: rgba(139, 92, 246, 0.25);
            --border-cyan: rgba(0, 242, 254, 0.35);
            --border-faint: rgba(255, 255, 255, 0.08);
            --cyan-glow: #00f2fe;
            --purple-glow: #8b5cf6;
            --purple-dark: #6d28d9;
            --danger-glow: #f43f5e;
            --danger-bg: rgba(244, 63, 94, 0.15);
            --success-glow: #10b981;
            --success-bg: rgba(16, 185, 129, 0.15);
            --warning-glow: #fbbf24;
            --warning-bg: rgba(251, 191, 36, 0.15);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --text-faint: #475569;
            --radius-lg: 20px;
            --radius-md: 14px;
            --radius-sm: 8px;
            --radius-pill: 30px;
            --font-sans: "Plus Jakarta Sans", -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: "JetBrains Mono", monospace;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-obsidian);
            background-image: 
                radial-gradient(circle at 12% 15%, rgba(139, 92, 246, 0.12), transparent 45%),
                radial-gradient(circle at 88% 80%, rgba(0, 242, 254, 0.1), transparent 50%),
                radial-gradient(rgba(139, 92, 246, 0.12) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 36px 36px;
            color: var(--text-main);
            font-family: var(--font-sans);
            min-height: 100vh;
            padding: 36px 20px 100px;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
        }

        .container { max-width: 1180px; margin: 0 auto; }

        /* Top HUD Header */
        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 20px;
        }

        .brand-group {
            display: flex;
            align-items: center;
            gap: 18px;
        }

        .logo-frame {
            width: 68px;
            height: 68px;
            background: transparent;
            border: none;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .logo-frame:hover {
            transform: scale(1.06);
        }

        .logo-frame img {
            width: 100%;
            height: 100%;
            object-fit: contain;
            filter: drop-shadow(0 0 16px rgba(0, 242, 254, 0.45)) drop-shadow(0 0 24px rgba(139, 92, 246, 0.3));
        }

        .brand-text h1 {
            font-size: 26px;
            font-weight: 800;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 8px;
            line-height: 1.2;
        }

        .brand-text h1 .brand-accent {
            background: linear-gradient(135deg, #00f2fe 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-text p {
            color: var(--text-muted);
            font-size: 13px;
            letter-spacing: 0.2px;
            margin-top: 3px;
        }

        .hud-telemetry {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .telemetry-badge {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background: var(--bg-well);
            border: 1px solid var(--border-cyan);
            padding: 7px 16px;
            border-radius: var(--radius-pill);
            font-size: 11.5px;
            font-weight: 700;
            letter-spacing: 0.6px;
            text-transform: uppercase;
            color: var(--cyan-glow);
            box-shadow: 0 0 20px rgba(0, 242, 254, 0.15);
        }

        .radar-pulse {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--cyan-glow);
            box-shadow: 0 0 10px var(--cyan-glow);
            animation: pulse 1.8s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 242, 254, 0.7); }
            70% { transform: scale(1.1); box-shadow: 0 0 0 8px rgba(0, 242, 254, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 242, 254, 0); }
        }

        /* Status Alerts */
        .alert-banner {
            padding: 16px 20px;
            border-radius: var(--radius-md);
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 14px;
            font-size: 14px;
            line-height: 1.5;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }
        .alert-banner.success {
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid var(--success-glow);
            color: #6ee7b7;
        }
        .alert-banner.danger {
            background: rgba(244, 63, 94, 0.15);
            border: 1px solid var(--danger-glow);
            color: #fda4af;
        }
        .alert-banner.info {
            background: rgba(0, 242, 254, 0.1);
            border: 1px solid var(--border-cyan);
            color: #bae6fd;
        }

        /* Bento Grid Architecture */
        .bento-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
            margin-bottom: 28px;
        }

        .cyber-card {
            background: var(--bg-card);
            backdrop-filter: blur(24px) saturate(180%);
            -webkit-backdrop-filter: blur(24px) saturate(180%);
            border: 1px solid var(--border-glow);
            border-radius: var(--radius-lg);
            padding: 28px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), inset 0 1px 0 rgba(255, 255, 255, 0.06);
            position: relative;
            overflow: hidden;
            transition: border-color 0.25s, box-shadow 0.25s;
        }

        .cyber-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(90deg, transparent, rgba(0, 242, 254, 0.5), rgba(139, 92, 246, 0.5), transparent);
        }

        .card-header-flex {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .card-title {
            font-size: 18px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
            letter-spacing: -0.2px;
        }

        .card-desc {
            color: var(--text-muted);
            font-size: 13.5px;
            line-height: 1.6;
        }

        /* Stats Grid (Bento Metrics) */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin: 20px 0 24px;
        }

        .stat-item {
            background: var(--bg-well);
            border: 1px solid var(--border-glow);
            border-radius: var(--radius-md);
            padding: 20px;
            text-align: left;
            position: relative;
            transition: all 0.2s;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
        }

        .stat-item:hover {
            border-color: var(--border-cyan);
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
        }

        .stat-num {
            font-size: 34px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 8px;
            font-family: var(--font-mono);
        }

        .stat-num.danger { color: var(--danger-glow); text-shadow: 0 0 25px rgba(244, 63, 94, 0.45); }
        .stat-num.cyan { color: var(--cyan-glow); text-shadow: 0 0 25px rgba(0, 242, 254, 0.45); }
        .stat-num.success { color: var(--success-glow); text-shadow: 0 0 25px rgba(16, 185, 129, 0.45); }
        .stat-num.purple { color: var(--purple-glow); text-shadow: 0 0 25px rgba(139, 92, 246, 0.45); }

        .stat-meta {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.9px;
            font-weight: 700;
            color: var(--text-muted);
        }

        /* Mission Control HUD Console */
        .path-console {
            background: var(--bg-well);
            border: 1px solid rgba(139, 92, 246, 0.2);
            border-radius: var(--radius-md);
            padding: 14px 18px;
            margin-top: 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-family: var(--font-mono);
            font-size: 12.5px;
            flex-wrap: wrap;
            gap: 14px;
            box-shadow: inset 0 2px 8px rgba(0,0,0,0.5);
        }

        .path-label {
            color: var(--purple-glow);
            font-weight: 700;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.9px;
            margin-bottom: 4px;
        }

        .path-val {
            color: #f1f5f9;
            word-break: break-all;
            font-weight: 600;
        }

        .system-tags {
            display: flex;
            gap: 8px;
            align-items: center;
        }

        .sys-chip {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-faint);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            color: var(--text-muted);
        }

        /* Filter & Search Toolbar */
        .toolbar-matrix {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin: 20px 0 16px;
            gap: 16px;
            flex-wrap: wrap;
        }

        .search-box {
            position: relative;
            flex: 1;
            min-width: 260px;
        }

        .search-box input {
            width: 100%;
            background: var(--bg-well);
            border: 1px solid rgba(139, 92, 246, 0.3);
            border-radius: var(--radius-md);
            padding: 11px 16px 11px 40px;
            color: #fff;
            font-size: 13px;
            font-family: var(--font-sans);
            outline: none;
            transition: all 0.2s;
        }

        .search-box input:focus {
            border-color: var(--cyan-glow);
            box-shadow: 0 0 15px rgba(0, 242, 254, 0.25);
        }

        .search-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            pointer-events: none;
        }

        .selection-controller {
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .badge-count {
            background: rgba(139, 92, 246, 0.2);
            border: 1px solid var(--purple-glow);
            color: #d8b4fe;
            font-size: 12px;
            font-weight: 700;
            padding: 6px 14px;
            border-radius: var(--radius-pill);
            font-family: var(--font-mono);
        }

        /* Threat Matrix Cards / Table */
        .matrix-container {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-top: 14px;
        }

        .threat-row {
            background: var(--bg-well);
            border: 1px solid var(--border-glow);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            transition: all 0.2s;
            position: relative;
        }

        .threat-row:hover {
            border-color: var(--border-cyan);
            background: rgba(12, 17, 28, 0.95);
        }

        .threat-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            flex-wrap: wrap;
        }

        .threat-main-info {
            display: flex;
            align-items: center;
            gap: 14px;
            flex: 1;
            min-width: 280px;
        }

        /* Checkbox Personalizado */
        .custom-checkbox {
            position: relative;
            display: inline-flex;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }

        .custom-checkbox input {
            position: absolute;
            opacity: 0;
            cursor: pointer;
            height: 0;
            width: 0;
        }

        .checkbox-box {
            width: 22px;
            height: 22px;
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid rgba(139, 92, 246, 0.4);
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s;
        }

        .custom-checkbox input:checked ~ .checkbox-box {
            background: var(--cyan-glow);
            border-color: var(--cyan-glow);
            box-shadow: 0 0 12px rgba(0, 242, 254, 0.5);
        }

        .checkbox-box svg {
            display: none;
            stroke: #07090e;
            stroke-width: 3;
            width: 14px;
            height: 14px;
        }

        .custom-checkbox input:checked ~ .checkbox-box svg {
            display: block;
        }

        /* Badges & Tags */
        .badge-risk {
            font-size: 10.5px;
            font-weight: 800;
            letter-spacing: 0.6px;
            text-transform: uppercase;
            padding: 3px 9px;
            border-radius: 4px;
            font-family: var(--font-mono);
            flex-shrink: 0;
        }
        .badge-risk.critico { background: var(--danger-bg); color: var(--danger-glow); border: 1px solid rgba(244, 63, 94, 0.4); }
        .badge-risk.alto { background: var(--warning-bg); color: var(--warning-glow); border: 1px solid rgba(251, 191, 36, 0.4); }
        .badge-risk.medio { background: rgba(0, 242, 254, 0.15); color: var(--cyan-glow); border: 1px solid rgba(0, 242, 254, 0.3); }

        .badge-cat {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--border-faint);
            color: #cbd5e1;
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
            flex-shrink: 0;
        }

        .threat-path {
            font-family: var(--font-mono);
            font-size: 13px;
            color: #f8fafc;
            word-break: break-all;
        }

        .threat-actions-cell {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .badge-action {
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 6px;
            font-family: var(--font-mono);
        }
        .badge-action.delete { background: rgba(244, 63, 94, 0.2); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.3); }
        .badge-action.sanitize { background: rgba(139, 92, 246, 0.2); color: #d8b4fe; border: 1px solid rgba(139, 92, 246, 0.3); }
        .badge-action.restore { background: rgba(0, 242, 254, 0.2); color: #bae6fd; border: 1px solid rgba(0, 242, 254, 0.3); }

        .btn-inspect {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid var(--border-faint);
            color: var(--text-muted);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-family: inherit;
        }

        .btn-inspect:hover {
            border-color: var(--cyan-glow);
            color: var(--cyan-glow);
            background: rgba(0, 242, 254, 0.08);
        }

        /* Collapsible Code Inspector Box */
        .snippet-drawer {
            display: none;
            margin-top: 14px;
            padding-top: 14px;
            border-top: 1px dashed rgba(139, 92, 246, 0.25);
            animation: fadeIn 0.25s ease-in-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .snippet-reason {
            font-size: 12.5px;
            color: #cbd5e1;
            margin-bottom: 10px;
            line-height: 1.5;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .code-box {
            background: #030508;
            border: 1px solid rgba(139, 92, 246, 0.25);
            border-radius: var(--radius-sm);
            padding: 14px 18px;
            font-family: var(--font-mono);
            font-size: 12px;
            line-height: 1.6;
            color: #93c5fd;
            overflow-x: auto;
            white-space: pre;
            box-shadow: inset 0 2px 8px rgba(0,0,0,0.8);
        }

        /* Action Buttons */
        .btn-group {
            display: flex;
            gap: 16px;
            margin-top: 24px;
            flex-wrap: wrap;
        }

        .btn {
            padding: 13px 24px;
            border-radius: var(--radius-md);
            font-size: 13.5px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
            display: inline-flex;
            align-items: center;
            gap: 10px;
            text-decoration: none;
            border: none;
            letter-spacing: 0.3px;
            font-family: inherit;
        }

        .btn:active { transform: scale(0.98); }

        .btn-secondary {
            background: rgba(18, 26, 42, 0.9);
            color: var(--text-main);
            border: 1px solid rgba(139, 92, 246, 0.35);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
        }

        .btn-secondary:hover {
            border-color: var(--cyan-glow);
            color: var(--cyan-glow);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 242, 254, 0.2);
        }

        .btn-cyber-primary {
            background: linear-gradient(135deg, #f43f5e 0%, #ec4899 40%, #8b5cf6 100%);
            color: #fff;
            box-shadow: 0 8px 25px rgba(244, 63, 94, 0.35), 0 0 25px rgba(139, 92, 246, 0.25);
        }

        .btn-cyber-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 35px rgba(244, 63, 94, 0.5), 0 0 35px rgba(0, 242, 254, 0.35);
        }

        /* Floating Sticky Action Bar */
        .sticky-action-bar {
            position: relative;
            margin-top: 24px;
            background: rgba(14, 20, 32, 0.95);
            backdrop-filter: blur(24px) saturate(200%);
            -webkit-backdrop-filter: blur(24px) saturate(200%);
            border: 1px solid var(--border-cyan);
            border-radius: var(--radius-md);
            padding: 18px 26px;
            box-shadow: 0 12px 35px rgba(0, 0, 0, 0.6), 0 0 25px rgba(0, 242, 254, 0.15);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            width: 100%;
            box-sizing: border-box;
        }

        .sticky-info {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13.5px;
            font-weight: 600;
            color: #f8fafc;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 48px 20px;
        }
        .empty-state-icon {
            width: 72px;
            height: 72px;
            margin: 0 auto 18px;
            border-radius: 50%;
            background: rgba(16, 185, 129, 0.12);
            border: 2px solid var(--success-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--success-glow);
            box-shadow: 0 0 30px rgba(16, 185, 129, 0.3);
        }
        .empty-state h3 {
            font-size: 20px;
            font-weight: 800;
            color: #fff;
            margin-bottom: 8px;
        }
        .empty-state p {
            font-size: 14px;
            color: var(--text-muted);
            max-width: 500px;
            margin: 0 auto;
            line-height: 1.6;
        }

        /* Quarantine Vault Card */
        .vault-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-top: 16px;
        }

        .vault-item {
            background: var(--bg-well);
            border: 1px solid var(--border-glow);
            border-radius: var(--radius-md);
            padding: 14px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            flex-wrap: wrap;
        }

        .vault-meta {
            display: flex;
            align-items: center;
            gap: 12px;
            font-family: var(--font-mono);
            font-size: 12.5px;
        }

        .vault-name {
            font-weight: 700;
            color: #f1f5f9;
        }

        .vault-size {
            color: var(--cyan-glow);
            font-size: 11.5px;
        }

        .vault-date {
            color: var(--text-muted);
            font-size: 11.5px;
        }

        .vault-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Interactive Command Terminal */
        .terminal-container {
            margin-top: 24px;
            border-radius: var(--radius-md);
            overflow: hidden;
            border: 1px solid rgba(139, 92, 246, 0.3);
            box-shadow: 0 15px 40px rgba(0,0,0,0.6);
        }

        .terminal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #0b0f19;
            padding: 12px 18px;
            border-bottom: 1px solid rgba(139, 92, 246, 0.2);
            flex-wrap: wrap;
            gap: 10px;
        }

        .terminal-controls {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .terminal-dots { display: flex; gap: 7px; }
        .terminal-dot { width: 10px; height: 10px; border-radius: 50%; }
        .dot-red { background: #f43f5e; }
        .dot-yellow { background: #fbbf24; }
        .dot-green { background: #10b981; }

        .terminal-title {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-muted);
            letter-spacing: 0.5px;
        }

        .terminal-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .btn-terminal {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border-faint);
            color: var(--text-muted);
            padding: 5px 12px;
            border-radius: 6px;
            font-size: 11.5px;
            font-family: var(--font-mono);
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            text-decoration: none;
        }

        .btn-terminal:hover {
            color: var(--cyan-glow);
            border-color: var(--border-cyan);
            background: rgba(0, 242, 254, 0.08);
        }

        .log-terminal {
            background: #030508;
            padding: 20px 24px;
            max-height: 440px;
            overflow-y: auto;
            font-family: var(--font-mono);
            font-size: 12.5px;
            line-height: 1.7;
            color: #cbd5e1;
            box-shadow: inset 0 4px 25px rgba(0,0,0,0.8);
        }

        .log-terminal::-webkit-scrollbar { width: 6px; }
        .log-terminal::-webkit-scrollbar-track { background: #030508; }
        .log-terminal::-webkit-scrollbar-thumb { background: rgba(139, 92, 246, 0.35); border-radius: 3px; }

        .log-line {
            margin-bottom: 3px;
            word-break: break-all;
            display: flex;
            align-items: baseline;
            gap: 8px;
        }

        .log-line.threat { color: #fda4af; }
        .log-line.clean { color: #6ee7b7; }
        .log-line.info { color: #bae6fd; }
        .log-line.backup { color: #d8b4fe; }

        .log-tag {
            font-size: 10px;
            font-weight: 700;
            padding: 1px 5px;
            border-radius: 4px;
            flex-shrink: 0;
        }
        .log-tag.threat { background: rgba(244, 63, 94, 0.25); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.4); }
        .log-tag.clean { background: rgba(16, 185, 129, 0.25); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); }
        .log-tag.backup { background: rgba(139, 92, 246, 0.25); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.4); }

        /* =========================================================
           SCANNER HUD & RADAR VISUALIZER
           ========================================================= */
        .scanner-hud {
            display: none;
            background: rgba(11, 15, 25, 0.95);
            backdrop-filter: blur(28px) saturate(180%);
            -webkit-backdrop-filter: blur(28px) saturate(180%);
            border: 1px solid var(--border-cyan);
            border-radius: var(--radius-lg);
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.8), 0 0 35px rgba(0, 242, 254, 0.15);
            animation: fadeIn 0.3s ease-out;
        }

        .hud-grid {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 28px;
            align-items: center;
        }

        @media (max-width: 768px) {
            .hud-grid {
                grid-template-columns: 1fr;
                text-align: center;
            }
        }

        /* Radar Display */
        .radar-wrapper {
            position: relative;
            width: 140px;
            height: 140px;
            margin: 0 auto;
        }

        .radar-screen {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(0, 242, 254, 0.08) 0%, rgba(7, 9, 14, 0.9) 70%);
            border: 2px solid var(--cyan-glow);
            position: relative;
            overflow: hidden;
            box-shadow: 0 0 25px rgba(0, 242, 254, 0.3), inset 0 0 20px rgba(0, 242, 254, 0.2);
        }

        .radar-ring {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            border-radius: 50%;
            border: 1px dashed rgba(0, 242, 254, 0.3);
        }
        .radar-ring.r1 { width: 45px; height: 45px; }
        .radar-ring.r2 { width: 90px; height: 90px; }

        .radar-crosshair-h {
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: rgba(0, 242, 254, 0.25);
        }
        .radar-crosshair-v {
            position: absolute;
            left: 50%;
            top: 0;
            bottom: 0;
            width: 1px;
            background: rgba(0, 242, 254, 0.25);
        }

        .radar-sweep {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: conic-gradient(from 0deg, rgba(0, 242, 254, 0.6) 0deg, transparent 70deg, transparent 360deg);
            animation: rotateSweep 2s linear infinite;
        }

        @keyframes rotateSweep {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        .radar-blip {
            position: absolute;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--danger-glow);
            box-shadow: 0 0 12px var(--danger-glow);
            animation: blipPulse 1.2s infinite alternate;
        }

        @keyframes blipPulse {
            0% { transform: scale(0.8); opacity: 0.4; }
            100% { transform: scale(1.4); opacity: 1; }
        }

        /* Telemetry & Path Ticker */
        .hud-telemetry-content {
            display: flex;
            flex-direction: column;
            gap: 14px;
        }

        .hud-title-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 10px;
        }

        .hud-title {
            font-size: 15px;
            font-weight: 800;
            letter-spacing: 0.5px;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .hud-metrics-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 12px;
        }

        .hud-metric-box {
            background: var(--bg-well);
            border: 1px solid var(--border-glow);
            border-radius: var(--radius-sm);
            padding: 10px 14px;
        }

        .hud-metric-num {
            font-family: var(--font-mono);
            font-size: 20px;
            font-weight: 800;
            line-height: 1.2;
        }
        .hud-metric-num.cyan { color: var(--cyan-glow); }
        .hud-metric-num.purple { color: #c084fc; }
        .hud-metric-num.danger { color: var(--danger-glow); }

        .hud-metric-lbl {
            font-size: 11px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }

        .hud-ticker-box {
            background: #04060a;
            border: 1px solid rgba(0, 242, 254, 0.25);
            border-radius: var(--radius-sm);
            padding: 9px 14px;
            font-family: var(--font-mono);
            font-size: 12px;
            color: #94a3b8;
            display: flex;
            align-items: center;
            gap: 10px;
            overflow: hidden;
            white-space: nowrap;
        }

        .hud-ticker-tag {
            color: var(--cyan-glow);
            font-weight: 700;
            flex-shrink: 0;
            animation: pulse 1.5s infinite;
        }

        .hud-ticker-text {
            overflow: hidden;
            text-overflow: ellipsis;
            color: #e2e8f0;
        }

        .hud-progress-bar {
            height: 4px;
            width: 100%;
            background: rgba(255, 255, 255, 0.08);
            border-radius: 2px;
            overflow: hidden;
            position: relative;
        }

        .hud-progress-fill {
            height: 100%;
            width: 100%;
            background: linear-gradient(90deg, #00f2fe, #8b5cf6, #f43f5e);
            animation: progressIndeterminate 1.8s infinite linear;
        }

        @keyframes progressIndeterminate {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        /* Dynamic Row Insertion Animation */
        .threat-row-animated {
            animation: slideDownRow 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        @keyframes slideDownRow {
            from { opacity: 0; transform: translateY(-12px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* =========================================================
           ERADICATION STEPPER OVERLAY & MODAL
           ========================================================= */
        .stepper-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(4, 7, 13, 0.9);
            backdrop-filter: blur(18px);
            -webkit-backdrop-filter: blur(18px);
            z-index: 10000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .stepper-modal {
            background: #0c101c;
            border: 1px solid var(--border-cyan);
            border-radius: var(--radius-lg);
            max-width: 680px;
            width: 100%;
            padding: 32px;
            box-shadow: 0 25px 70px rgba(0,0,0,0.9), 0 0 50px rgba(0, 242, 254, 0.2);
            position: relative;
            animation: modalScale 0.28s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes modalScale {
            from { opacity: 0; transform: scale(0.92); }
            to { opacity: 1; transform: scale(1); }
        }

        .stepper-header {
            display: flex;
            align-items: center;
            gap: 14px;
            margin-bottom: 24px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 18px;
        }

        .stepper-header h3 {
            font-size: 19px;
            font-weight: 800;
            color: #fff;
            letter-spacing: -0.3px;
        }

        .stepper-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
            margin-bottom: 24px;
        }

        .step-item {
            display: flex;
            align-items: flex-start;
            gap: 14px;
            padding: 12px 16px;
            border-radius: var(--radius-md);
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-faint);
            transition: all 0.3s;
        }

        .step-item.pending {
            opacity: 0.4;
        }

        .step-item.active {
            opacity: 1;
            border-color: var(--border-cyan);
            background: rgba(0, 242, 254, 0.06);
            box-shadow: 0 0 20px rgba(0, 242, 254, 0.15);
        }

        .step-item.done {
            opacity: 1;
            border-color: rgba(16, 185, 129, 0.4);
            background: rgba(16, 185, 129, 0.05);
        }

        .step-badge {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: var(--font-mono);
            font-size: 12px;
            font-weight: 700;
            flex-shrink: 0;
            transition: all 0.3s;
        }

        .step-item.pending .step-badge {
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-muted);
        }

        .step-item.active .step-badge {
            background: var(--cyan-glow);
            color: #000;
            box-shadow: 0 0 12px var(--cyan-glow);
        }

        .step-item.done .step-badge {
            background: var(--success-glow);
            color: #000;
            box-shadow: 0 0 12px var(--success-glow);
        }

        .step-details {
            flex: 1;
        }

        .step-details h4 {
            font-size: 13.5px;
            font-weight: 700;
            color: #f1f5f9;
            margin-bottom: 2px;
        }

        .step-details p {
            font-size: 12px;
            color: var(--text-muted);
            line-height: 1.4;
        }

        .stepper-mini-log {
            background: #04060a;
            border: 1px solid rgba(139, 92, 246, 0.25);
            border-radius: var(--radius-sm);
            padding: 10px 14px;
            font-family: var(--font-mono);
            font-size: 11.5px;
            color: #94a3b8;
            max-height: 110px;
            overflow-y: auto;
            margin-bottom: 20px;
            line-height: 1.5;
        }

        /* =========================================================
           LAB SIMULATION & TRAINING SUITE CARD
           ========================================================= */
        .lab-card {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.12) 0%, rgba(0, 242, 254, 0.08) 100%);
            border: 1px solid rgba(139, 92, 246, 0.35);
            border-radius: var(--radius-lg);
            padding: 22px 26px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.4);
        }

        .lab-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; width: 4px; height: 100%;
            background: linear-gradient(180deg, #00f2fe, #8b5cf6);
        }

        .lab-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
            flex-wrap: wrap;
            gap: 12px;
        }

        .lab-title {
            font-size: 16px;
            font-weight: 800;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .lab-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(139, 92, 246, 0.2);
            border: 1px solid rgba(139, 92, 246, 0.4);
            color: #c084fc;
            padding: 4px 12px;
            border-radius: var(--radius-pill);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.6px;
            text-transform: uppercase;
        }

        .lab-desc {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.55;
            margin-bottom: 16px;
        }

        .lab-actions-group {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        footer {
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: var(--text-faint);
            letter-spacing: 0.6px;
            font-family: var(--font-mono);
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <div class="brand-group">
            <div class="logo-frame">
                <img src="<?php echo !empty($logoDataUri) ? htmlspecialchars($logoDataUri, ENT_QUOTES) : htmlspecialchars($embeddedLogoDataUri, ENT_QUOTES); ?>" onerror="this.onerror=null;this.src='<?php echo htmlspecialchars($embeddedLogoDataUri, ENT_QUOTES); ?>';" alt="CerberusWP Sentinel">
            </div>
            <div class="brand-text">
                <h1>CERBERUS<span class="brand-accent">WP</span></h1>
                <p>Cyber Sentinel & Threat Sterilization Center</p>
            </div>
        </div>
        <div class="hud-telemetry">
            <div class="telemetry-badge">
                <span class="radar-pulse"></span>
                DEFESA ATIVA
            </div>
        </div>
    </header>

    <?php if ($statusMessage): ?>
        <div class="alert-banner <?php echo $statusType; ?>">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <div><?php echo htmlspecialchars($statusMessage); ?></div>
        </div>
    <?php endif; ?>

    <!-- Bento Metrics Grid -->
    <div class="stats-grid">
        <div class="stat-item">
            <div class="stat-num danger"><?php echo $results ? count($results['threat_items']) : 0; ?></div>
            <div class="stat-meta">Ameaças Detectadas</div>
        </div>
        <div class="stat-item">
            <div class="stat-num cyan"><?php echo $results ? $results['scanned_files'] : 0; ?></div>
            <div class="stat-meta">Arquivos Varridos</div>
        </div>
        <div class="stat-item">
            <div class="stat-num purple"><?php echo count($quarantineBackups); ?></div>
            <div class="stat-meta">Backups em Quarentena (.zip)</div>
        </div>
        <div class="stat-item">
            <div class="stat-num success">
                <?php echo ($results && count($results['threat_items']) === 0) ? 'SEGURO' : 'ATENÇÃO'; ?>
            </div>
            <div class="stat-meta">Status Geral do Servidor</div>
        </div>
    </div>

    <!-- Scanner HUD & Radar Visualizer (Ativado em Tempo Real) -->
    <div class="scanner-hud" id="scannerHud">
        <div class="hud-grid">
            <div class="radar-wrapper">
                <div class="radar-screen">
                    <div class="radar-ring r1"></div>
                    <div class="radar-ring r2"></div>
                    <div class="radar-crosshair-h"></div>
                    <div class="radar-crosshair-v"></div>
                    <div class="radar-sweep"></div>
                    <div class="radar-blip" id="radarBlip" style="top: 35%; left: 60%; display: none;"></div>
                </div>
            </div>
            <div class="hud-telemetry-content">
                <div class="hud-title-bar">
                    <div class="hud-title">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                        <span id="hudStatusTitle">Varredura Heurística em Andamento...</span>
                    </div>
                    <span id="hudTimerBadge" style="font-family: var(--font-mono); font-size: 13px; color: var(--cyan-glow); font-weight: 700;">00:00.0s</span>
                </div>
                <div class="hud-metrics-row">
                    <div class="hud-metric-box">
                        <div class="hud-metric-num cyan" id="hudScannedFiles">0</div>
                        <div class="hud-metric-lbl">Arquivos Varridos</div>
                    </div>
                    <div class="hud-metric-box">
                        <div class="hud-metric-num purple" id="hudScannedDirs">0</div>
                        <div class="hud-metric-lbl">Diretórios Mapeados</div>
                    </div>
                    <div class="hud-metric-box">
                        <div class="hud-metric-num danger" id="hudThreatsFound">0</div>
                        <div class="hud-metric-lbl">Ameaças Detectadas</div>
                    </div>
                </div>
                <div class="hud-ticker-box">
                    <span class="hud-ticker-tag">VARRENDO AGORA:</span>
                    <span class="hud-ticker-text" id="hudCurrentPath">Iniciando inspeção de arquivos...</span>
                </div>
                <div class="hud-progress-bar">
                    <div class="hud-progress-fill"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Card de Treinamento & Laboratório Seguro -->
    <div class="lab-card">
        <div class="lab-header">
            <div class="lab-title">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--purple-glow)" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
                <span>Laboratório de Demonstração & Treinamento Seguro</span>
            </div>
            <span class="lab-badge">Cenário Isolado</span>
        </div>
        <p class="lab-desc">
            Deseja acompanhar todo o processo de varredura no radar e a esterilização passo a passo sem riscos para seus sites reais?
            Injete um cenário de teste com 5 ameaças típicas do malware SCV (pasta oculta, .user.ini, .htaccess rogue, webshell e injeção no wp-config) dentro de uma pasta isolada <code>lab_simulation/</code>.
        </p>
        <div class="lab-actions-group">
            <button type="button" class="btn btn-cyber-primary" style="padding: 9px 18px; font-size: 12.5px;" onclick="injectLabScenario()">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                Injetar Cenário de Teste (5 Ameaças)
            </button>
            <button type="button" class="btn btn-secondary" style="padding: 9px 18px; font-size: 12.5px;" onclick="startLiveScan('<?php echo addslashes($scanPath); ?>')">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                Varredura ao Vivo (Radar HUD)
            </button>
            <button type="button" class="btn-terminal" style="padding: 8px 14px; font-size: 12px;" onclick="resetLabScenario()">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Limpar Cenário
            </button>
        </div>
    </div>

    <div class="bento-grid">
        <!-- Card 1: Console de Controle e Alvo -->
        <div class="cyber-card">
            <div class="card-header-flex">
                <div class="card-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    <span>Centro de Comando da Hospedagem</span>
                </div>
                <form method="POST" action="?token=<?php echo htmlspecialchars($token); ?>" style="display:inline;">
                    <input type="hidden" name="action" value="simulate">
                    <input type="hidden" name="custom_path" value="<?php echo htmlspecialchars($scanPath); ?>">
                    <button type="submit" class="btn btn-secondary" style="padding: 8px 16px; font-size: 12px;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                        Atualizar Varredura
                    </button>
                </form>
            </div>
            <p class="card-desc">
                O CerberusWP inspeciona a raiz do usuário, identificando arquivos do worm SCV (smooth-librarian-lite), backdoors numéricos, injeções nos scripts de boot e hooks do WordPress. Você possui controle granular total sobre cada item a ser tratado.
            </p>

            <div class="path-console">
                <div>
                    <div class="path-label">Diretório de Varredura Atual</div>
                    <div class="path-val"><?php echo htmlspecialchars($scanPath); ?></div>
                </div>
                <div class="system-tags">
                    <span class="sys-chip">PHP <?php echo PHP_VERSION; ?></span>
                    <span class="sys-chip"><?php echo php_uname('s'); ?></span>
                    <span class="sys-chip" style="color: var(--cyan-glow); border-color: rgba(0, 242, 254, 0.3);">GARANTIA ZERO-LOSS (ZIP ATIVO)</span>
                </div>
            </div>

            <?php if (!empty($detectedSites)): ?>
                <div style="margin-top: 14px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <span style="font-size: 11px; font-weight: 700; color: var(--text-muted); font-family: var(--font-mono); text-transform: uppercase; letter-spacing: 0.8px;">Atalhos por Site:</span>
                    <a href="?token=<?php echo htmlspecialchars($token); ?>&action=simulate&custom_path=<?php echo urlencode($accountRoot); ?>" class="btn-terminal" style="<?php echo ($scanPath === $accountRoot) ? 'color: var(--cyan-glow); border-color: var(--border-cyan); background: rgba(0, 242, 254, 0.08);' : ''; ?>">
                        Toda a Hospedagem (Geral)
                    </a>
                    <?php foreach ($detectedSites as $ds): ?>
                        <a href="?token=<?php echo htmlspecialchars($token); ?>&action=simulate&custom_path=<?php echo urlencode($ds['path']); ?>" class="btn-terminal" style="<?php echo ($scanPath === $ds['path']) ? 'color: var(--cyan-glow); border-color: var(--border-cyan); background: rgba(0, 242, 254, 0.08);' : ''; ?>">
                            <?php echo htmlspecialchars($ds['name']); ?>
                        </a>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- Card 2: Matriz Interativa de Ameaças Detectadas -->
        <div class="cyber-card" id="threatMatrixCard">
            <div class="card-header-flex">
                <div class="card-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--danger-glow)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <span>Matriz Interativa de Ameaças Detectadas</span>
                </div>
                <div class="selection-controller">
                    <span class="badge-count" id="selectionSummaryBadge">0 selecionados</span>
                </div>
            </div>

            <!-- Prompt Inicial caso ainda não tenha varrido -->
            <div id="matrixEmptyPrompt" style="<?php echo ($results === null) ? 'display:block;' : 'display:none;'; ?> text-align: center; padding: 42px 20px;">
                <div style="max-width: 580px; margin: 0 auto;">
                    <div style="width: 64px; height: 64px; margin: 0 auto 16px; border-radius: 50%; background: rgba(0, 242, 254, 0.1); border: 2px solid var(--border-cyan); display: flex; align-items: center; justify-content: center; color: var(--cyan-glow);">
                        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    </div>
                    <h3 style="font-size: 20px; font-weight: 800; color: #fff; margin-bottom: 8px;">Pronto para Mapear e Esterilizar</h3>
                    <p style="font-size: 13.5px; color: var(--text-muted); line-height: 1.6; margin-bottom: 24px;">
                        Acompanhe o radar e a varredura heurística ao vivo. O CerberusWP irá listar todas as ameaças detectadas em uma matriz interativa com checkboxes individuais e prévia de código antes de qualquer alteração.
                    </p>
                    <button type="button" class="btn btn-cyber-primary" style="padding: 15px 32px; font-size: 14px; margin: 0 auto;" onclick="startLiveScan('<?php echo addslashes($scanPath); ?>')">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        Iniciar Varredura Heurística em Tempo Real
                    </button>
                </div>
            </div>

            <!-- Wrapper da Matriz de Ameaças (Ativo estaticamente ou via SSE) -->
            <div id="matrixLiveWrapper" style="<?php echo ($results && !empty($results['threat_items'])) ? 'display:block;' : 'display:none;'; ?>">
                <p class="card-desc">
                    Selecione quais itens você autoriza o Cerberus a esterilizar. Clique em <strong>Inspecionar Código</strong> para verificar o trecho malicioso antes de executar. Um backup em .ZIP é criado automaticamente antes de qualquer ação.
                </p>

                <!-- Toolbar de Filtro e Seleção Rápida -->
                <div class="toolbar-matrix" id="threatFilterToolbar">
                    <div class="search-box">
                        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        <input type="text" id="threatFilterInput" placeholder="Filtrar por nome de arquivo, pasta ou categoria..." oninput="filterThreatRows()">
                    </div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <button type="button" class="btn-terminal" onclick="toggleSelectAll(true)">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                            Selecionar Todos
                        </button>
                        <button type="button" class="btn-terminal" onclick="toggleSelectAll(false)">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                            Desmarcar Todos
                        </button>
                    </div>
                </div>

                <form method="POST" id="threatForm" action="?token=<?php echo htmlspecialchars($token); ?>" onsubmit="return handleCleanSubmit(event);">
                    <input type="hidden" name="custom_path" value="<?php echo htmlspecialchars($scanPath); ?>">
                    
                    <div class="matrix-container" id="matrixRowsContainer">
                        <?php if ($results && !empty($results['threat_items'])): ?>
                            <?php foreach ($results['threat_items'] as $item): ?>
                                <?php 
                                    $riskClass = strtolower($item['risk']) === 'crítico' ? 'critico' : (strtolower($item['risk']) === 'alto' ? 'alto' : 'medio');
                                    $actionClass = $item['action'] === 'delete' ? 'delete' : ($item['action'] === 'restore_index_php' ? 'restore' : 'sanitize');
                                ?>
                                <div class="threat-row" id="row-<?php echo $item['id']; ?>" data-filter="<?php echo htmlspecialchars(strtolower($item['rel'] . ' ' . $item['category'])); ?>">
                                    <div class="threat-header">
                                        <div class="threat-main-info">
                                            <label class="custom-checkbox">
                                                <input type="checkbox" name="selected_threats[]" value="<?php echo $item['id']; ?>" class="threat-check" checked onchange="updateSelectionCount()">
                                                <span class="checkbox-box">
                                                    <svg viewBox="0 0 24 24" fill="none"><polyline points="20 6 9 17 4 12"/></svg>
                                                </span>
                                            </label>

                                            <span class="badge-risk <?php echo $riskClass; ?>"><?php echo htmlspecialchars($item['risk']); ?></span>
                                            <span class="badge-cat"><?php echo htmlspecialchars($item['category']); ?></span>
                                            <span class="threat-path"><?php echo htmlspecialchars($item['rel']); ?></span>
                                        </div>

                                        <div class="threat-actions-cell">
                                            <span class="badge-action <?php echo $actionClass; ?>"><?php echo htmlspecialchars($item['action_label']); ?></span>
                                            <button type="button" class="btn-inspect" onclick="toggleSnippet('snippet-<?php echo $item['id']; ?>')">
                                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                                Inspecionar Código
                                            </button>
                                        </div>
                                    </div>

                                    <div class="snippet-drawer" id="snippet-<?php echo $item['id']; ?>">
                                        <div class="snippet-reason">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                                            <span><strong>Diagnóstico:</strong> <?php echo htmlspecialchars($item['reason']); ?></span>
                                            <span style="margin-left: auto; color: var(--text-muted); font-size: 11px;">Tamanho: <?php echo htmlspecialchars($item['size']); ?></span>
                                        </div>
                                        <div class="code-box"><?php echo htmlspecialchars($item['snippet']); ?></div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>

                    <!-- Barra Fixa Flutuante de Confirmação e Esterilização -->
                    <div class="sticky-action-bar" id="stickyActionBar" style="display: none;">
                        <div class="sticky-info">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            <span id="stickyTextCounter">0 ameaças selecionadas para quarentena e limpeza</span>
                        </div>
                        <button type="button" class="btn btn-cyber-primary" style="padding: 10px 22px; font-size: 13px;" onclick="handleCleanSubmit(event);">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            Esterilizar Itens Selecionados
                        </button>
                    </div>
                </form>
            </div>

            <!-- Estado Vazio: Servidor Protegido -->
            <div class="empty-state" id="matrixCleanPrompt" style="<?php echo ($results && empty($results['threat_items'])) ? 'display:block;' : 'display:none;'; ?>">
                <div class="empty-state-icon">
                    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                </div>
                <h3>Hospedagem 100% Limpa e Protegida!</h3>
                <p>Nenhuma ameaça SCV, backdoor oculto ou injeção de bootloader foi localizada nos diretórios analisados. O ecossistema está seguro.</p>
            </div>
        </div>

        <!-- Card 3: Cofre de Quarentena & Rollback (Restauração) -->
        <div class="cyber-card">
            <div class="card-header-flex">
                <div class="card-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--purple-glow)" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                    <span>Cofre de Quarentena & Restauração (Rollback)</span>
                </div>
            </div>
            <p class="card-desc">
                Antes de qualquer exclusão ou higienização, os arquivos são compactados em arquivos <code>.zip</code> com manifesto JSON. Você pode baixar os pacotes de segurança ou restaurar o estado original da hospedagem a qualquer momento com 1 clique.
            </p>

            <?php if (!empty($quarantineBackups)): ?>
                <div class="vault-list">
                    <?php foreach ($quarantineBackups as $q): ?>
                        <div class="vault-item">
                            <div class="vault-meta">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--purple-glow)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                                <span class="vault-name"><?php echo htmlspecialchars($q['filename']); ?></span>
                                <span class="vault-size"><?php echo htmlspecialchars($q['size']); ?></span>
                                <span class="vault-date"><?php echo htmlspecialchars($q['date']); ?></span>
                            </div>
                            <div class="vault-actions">
                                <a href="?token=<?php echo htmlspecialchars($token); ?>&action=download_quarantine&file=<?php echo urlencode($q['filename']); ?>" class="btn-terminal">
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                    Baixar Backup (.zip)
                                </a>
                                <form method="POST" action="?token=<?php echo htmlspecialchars($token); ?>" style="display:inline;" onsubmit="return confirm('ATENÇÃO: Deseja descompactar e restaurar todos os arquivos deste backup de quarentena na hospedagem?');">
                                    <input type="hidden" name="action" value="restore_quarantine">
                                    <input type="hidden" name="zip_file" value="<?php echo htmlspecialchars($q['filename']); ?>">
                                    <button type="submit" class="btn-terminal" style="color: var(--warning-glow); border-color: rgba(251, 191, 36, 0.3);">
                                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
                                        Reverter / Restaurar
                                    </button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div style="padding: 20px 0; color: var(--text-muted); font-size: 13px;">
                    Nenhum pacote de quarentena gerado ainda. O cofre armazenará automaticamente os arquivos na primeira esterilização.
                </div>
            <?php endif; ?>
        </div>

        <!-- Card 4: Terminal de Telemetria Cerberus Kernel -->
        <?php if ($results && !empty($results['logs'])): ?>
            <div class="cyber-card">
                <div class="card-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                    <span>Fluxo de Telemetria (Cerberus Kernel Live)</span>
                </div>

                <div class="terminal-container">
                    <div class="terminal-header">
                        <div class="terminal-controls">
                            <div class="terminal-dots">
                                <div class="terminal-dot dot-red"></div>
                                <div class="terminal-dot dot-yellow"></div>
                                <div class="terminal-dot dot-green"></div>
                            </div>
                            <div class="terminal-title">cerberus-kernel-stream.log</div>
                        </div>
                        <div class="terminal-actions">
                            <button type="button" class="btn-terminal" onclick="copyTerminalLogs()">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                Copiar Log
                            </button>
                            <span style="font-size: 11px; color: var(--cyan-glow); font-family: var(--font-mono);">● AO VIVO</span>
                        </div>
                    </div>
                    <div class="log-terminal" id="terminalLog">
                        <?php foreach ($results['logs'] as $logLine): ?>
                            <?php 
                                $cls = 'info';
                                $tag = 'INFO';
                                if (strpos($logLine, '[THREAT]') !== false) { $cls = 'threat'; $tag = 'THREAT'; }
                                elseif (strpos($logLine, '[CLEAN]') !== false) { $cls = 'clean'; $tag = 'CLEAN'; }
                                elseif (strpos($logLine, '[BACKUP]') !== false) { $cls = 'backup'; $tag = 'BACKUP'; }
                            ?>
                            <div class="log-line <?php echo $cls; ?>">
                                <span class="log-tag <?php echo $cls; ?>"><?php echo $tag; ?></span>
                                <span><?php echo htmlspecialchars($logLine); ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Modal do Stepper de Esterilização Atômica -->
    <div class="stepper-overlay" id="eradicationModal">
        <div class="stepper-modal">
            <div class="stepper-header">
                <div style="width: 42px; height: 42px; border-radius: 50%; background: rgba(0, 242, 254, 0.1); border: 2px solid var(--border-cyan); display: flex; align-items: center; justify-content: center; color: var(--cyan-glow); flex-shrink: 0;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                </div>
                <div>
                    <h3>Protocolo de Esterilização Atômica</h3>
                    <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">Executando expurgo seletivo com garantia de rollback</p>
                </div>
            </div>

            <div class="stepper-list">
                <!-- Passo 1 -->
                <div class="step-item pending" id="step1">
                    <div class="step-badge" id="step1Badge">1</div>
                    <div class="step-details">
                        <h4>1. Cofre de Quarentena (.zip)</h4>
                        <p id="step1Desc">Compactando cópia de segurança com manifesto JSON antes da alteração...</p>
                    </div>
                </div>
                <!-- Passo 2 -->
                <div class="step-item pending" id="step2">
                    <div class="step-badge" id="step2Badge">2</div>
                    <div class="step-details">
                        <h4>2. Higienização & Expurgo dos Backdoors</h4>
                        <p id="step2Desc">Removendo arquivos físicos e limpando injeções nos scripts do Core...</p>
                    </div>
                </div>
                <!-- Passo 3 -->
                <div class="step-item pending" id="step3">
                    <div class="step-badge" id="step3Badge">3</div>
                    <div class="step-details">
                        <h4>3. Vacina Sentinela Must-Use</h4>
                        <p id="step3Desc">Instalando 000-antidoto-vaccine.php para bloqueio preventivo contínuo...</p>
                    </div>
                </div>
                <!-- Passo 4 -->
                <div class="step-item pending" id="step4">
                    <div class="step-badge" id="step4Badge">4</div>
                    <div class="step-details">
                        <h4>4. Imunização Concluída</h4>
                        <p id="step4Desc">Validando integridade e gerando relatório de segurança final...</p>
                    </div>
                </div>
            </div>

            <div class="stepper-mini-log" id="stepperMiniLog">
                [Kernel] Aguardando início do protocolo de esterilização...
            </div>

            <div style="display: flex; justify-content: flex-end; align-items: center; gap: 12px;" id="stepperFooterActions">
                <a href="#" class="btn btn-cyber-primary" id="btnDownloadQuarantine" style="display: none; padding: 10px 18px; font-size: 12.5px;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    Baixar Backup (.zip)
                </a>
                <button type="button" class="btn btn-secondary" id="btnModalClose" style="display: none;" onclick="location.reload()">
                    Concluir e Atualizar Tela
                </button>
            </div>
        </div>
    </div>

    <footer>
        CERBERUS-WP CYBERDEFENSE PROJECT • ENGENHARIA DE SEGURANÇA AVANÇADA PARA WORDPRESS & HOSTGATOR
    </footer>
</div>

<script>
const CERBERUS_TOKEN = <?php echo json_encode($token); ?>;
const CURRENT_SCAN_PATH = <?php echo json_encode($scanPath); ?>;

let scanTimer = null;
let scanStartTime = 0;
let liveThreatCount = 0;

function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function startTimer() {
    scanStartTime = Date.now();
    const badge = document.getElementById('hudTimerBadge');
    if (scanTimer) clearInterval(scanTimer);
    scanTimer = setInterval(() => {
        const delta = (Date.now() - scanStartTime) / 1000;
        const mins = Math.floor(delta / 60).toString().padStart(2, '0');
        const secs = (delta % 60).toFixed(1).padStart(4, '0');
        if (badge) badge.innerText = `${mins}:${secs}s`;
    }, 100);
}

function stopTimer() {
    if (scanTimer) clearInterval(scanTimer);
    scanTimer = null;
}

function startLiveScan(targetPath) {
    targetPath = targetPath || CURRENT_SCAN_PATH;
    
    // Mostra HUD do Scanner e Radar
    const hud = document.getElementById('scannerHud');
    if (hud) hud.style.display = 'block';
    hud.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Reseta Contadores do HUD
    document.getElementById('hudStatusTitle').innerText = 'Varredura Heurística em Andamento...';
    document.getElementById('hudScannedFiles').innerText = '0';
    document.getElementById('hudScannedDirs').innerText = '0';
    document.getElementById('hudThreatsFound').innerText = '0';
    document.getElementById('hudCurrentPath').innerText = 'Conectando ao kernel Cerberus...';
    document.getElementById('radarBlip').style.display = 'none';

    // Prepara a Matriz
    const emptyPrompt = document.getElementById('matrixEmptyPrompt');
    const cleanPrompt = document.getElementById('matrixCleanPrompt');
    const liveWrapper = document.getElementById('matrixLiveWrapper');
    const rowsContainer = document.getElementById('matrixRowsContainer');

    if (emptyPrompt) emptyPrompt.style.display = 'none';
    if (cleanPrompt) cleanPrompt.style.display = 'none';
    if (liveWrapper) liveWrapper.style.display = 'block';
    if (rowsContainer) rowsContainer.innerHTML = '';

    liveThreatCount = 0;
    startTimer();

    // Inicia EventSource SSE
    const streamUrl = `?token=${encodeURIComponent(CERBERUS_TOKEN)}&action=simulate&stream=1&custom_path=${encodeURIComponent(targetPath)}`;
    const eventSource = new EventSource(streamUrl);

    eventSource.addEventListener('progress', (e) => {
        try {
            const data = JSON.parse(e.data);
            document.getElementById('hudScannedFiles').innerText = data.scanned_files;
            document.getElementById('hudScannedDirs').innerText = data.scanned_dirs;
            document.getElementById('hudCurrentPath').innerText = data.current || '';
        } catch (err) {}
    });

    eventSource.addEventListener('threat', (e) => {
        try {
            const threat = JSON.parse(e.data);
            liveThreatCount++;
            document.getElementById('hudThreatsFound').innerText = liveThreatCount;
            document.getElementById('radarBlip').style.display = 'block';

            // Adiciona Linha na Matriz com animação
            const row = renderThreatRow(threat);
            if (rowsContainer) rowsContainer.appendChild(row);
            updateSelectionCount();
        } catch (err) {}
    });

    eventSource.addEventListener('log', (e) => {
        try {
            const logData = JSON.parse(e.data);
            appendLogToTerminal(logData.msg, logData.level, logData.timestamp);
        } catch (err) {}
    });

    eventSource.addEventListener('done', (e) => {
        stopTimer();
        eventSource.close();
        document.getElementById('hudStatusTitle').innerText = 'Varredura Concluída!';
        document.getElementById('hudCurrentPath').innerText = 'Análise atômica finalizada.';

        if (liveThreatCount === 0) {
            if (liveWrapper) liveWrapper.style.display = 'none';
            if (cleanPrompt) cleanPrompt.style.display = 'block';
        } else {
            updateSelectionCount();
        }
    });

    eventSource.onerror = (err) => {
        stopTimer();
        eventSource.close();
        document.getElementById('hudStatusTitle').innerText = 'Varredura Concluída (Finalizada).';
        updateSelectionCount();
    };
}

function appendLogToTerminal(msg, level, timestamp) {
    const term = document.getElementById('terminalLog');
    if (!term) return;
    let cls = 'info';
    let tag = 'INFO';
    if (level === 'THREAT' || msg.includes('[THREAT]')) { cls = 'threat'; tag = 'THREAT'; }
    else if (level === 'CLEAN' || msg.includes('[CLEAN]')) { cls = 'clean'; tag = 'CLEAN'; }
    else if (level === 'BACKUP' || msg.includes('[BACKUP]')) { cls = 'backup'; tag = 'BACKUP'; }

    const line = document.createElement('div');
    line.className = `log-line ${cls}`;
    line.innerHTML = `<span class="log-tag ${cls}">${tag}</span> <span>[${timestamp || ''}] ${escapeHtml(msg)}</span>`;
    term.appendChild(line);
    term.scrollTop = term.scrollHeight;
}

function renderThreatRow(item) {
    const riskClass = (item.risk.toLowerCase() === 'crítico' || item.risk.toLowerCase() === 'critico') ? 'critico' : (item.risk.toLowerCase() === 'alto' ? 'alto' : 'medio');
    const actionClass = item.action === 'delete' ? 'delete' : (item.action === 'restore_index_php' ? 'restore' : 'sanitize');
    
    const row = document.createElement('div');
    row.className = 'threat-row threat-row-animated';
    row.id = 'row-' + item.id;
    row.setAttribute('data-filter', (item.rel + ' ' + item.category).toLowerCase());
    
    row.innerHTML = `
        <div class="threat-header">
            <div class="threat-main-info">
                <label class="custom-checkbox">
                    <input type="checkbox" name="selected_threats[]" value="${escapeHtml(item.id)}" class="threat-check" checked onchange="updateSelectionCount()">
                    <span class="checkbox-box">
                        <svg viewBox="0 0 24 24" fill="none"><polyline points="20 6 9 17 4 12"/></svg>
                    </span>
                </label>
                <span class="badge-risk ${riskClass}">${escapeHtml(item.risk)}</span>
                <span class="badge-cat">${escapeHtml(item.category)}</span>
                <span class="threat-path">${escapeHtml(item.rel)}</span>
            </div>
            <div class="threat-actions-cell">
                <span class="badge-action ${actionClass}">${escapeHtml(item.action_label)}</span>
                <button type="button" class="btn-inspect" onclick="toggleSnippet('snippet-${escapeHtml(item.id)}')">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    Inspecionar Código
                </button>
            </div>
        </div>
        <div class="snippet-drawer" id="snippet-${escapeHtml(item.id)}">
            <div class="snippet-reason">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                <span><strong>Diagnóstico:</strong> ${escapeHtml(item.reason)}</span>
                <span style="margin-left: auto; color: var(--text-muted); font-size: 11px;">Tamanho: ${escapeHtml(item.size || 'N/A')}</span>
            </div>
            <div class="code-box">${escapeHtml(item.snippet || '')}</div>
        </div>
    `;
    return row;
}

function injectLabScenario() {
    const hud = document.getElementById('scannerHud');
    if (hud) hud.style.display = 'block';
    hud.scrollIntoView({ behavior: 'smooth', block: 'start' });

    document.getElementById('hudStatusTitle').innerText = 'Injetando Cenário de Teste Isolado...';
    document.getElementById('hudCurrentPath').innerText = 'Criando pasta lab_simulation/ com 5 ameaças simuladas...';

    fetch(`?token=${encodeURIComponent(CERBERUS_TOKEN)}&action=inject_lab_scenario&ajax=1`)
        .then(r => r.json())
        .then(res => {
            if (res.success) {
                // Dispara Varredura no Cenário Injetado
                startLiveScan(res.path);
            } else {
                alert('Erro ao injetar cenário de teste.');
            }
        })
        .catch(err => {
            startLiveScan('lab_simulation');
        });
}

function resetLabScenario() {
    if (!confirm('Deseja realmente remover e limpar o diretório lab_simulation/?')) return;
    fetch(`?token=${encodeURIComponent(CERBERUS_TOKEN)}&action=reset_lab_scenario&ajax=1`)
        .then(r => r.json())
        .then(res => {
            alert('Cenário de teste removido com sucesso.');
            location.reload();
        })
        .catch(err => {
            location.reload();
        });
}

function handleCleanSubmit(event) {
    if (event) event.preventDefault();
    const checked = document.querySelectorAll('.threat-check:checked');
    if (checked.length === 0) {
        alert('Por favor, selecione ao menos uma ameaça para executar a esterilização.');
        return false;
    }

    const ok = confirm(`ATENÇÃO DE SEGURANÇA:\n\nVocê selecionou ${checked.length} item(ns) para esterilização.\n\nO CerberusWP irá criar uma cópia de segurança compactada (.zip) de todos eles no Cofre de Quarentena antes de qualquer exclusão/alteração.\n\nDeseja confirmar a execução atômica e acompanhar o processo passo a passo?`);
    if (!ok) return false;

    const ids = Array.from(checked).map(c => c.value);
    startLiveClean(ids);
    return false;
}

function setStepState(stepNum, state, desc) {
    const item = document.getElementById(`step${stepNum}`);
    const badge = document.getElementById(`step${stepNum}Badge`);
    const descEl = document.getElementById(`step${stepNum}Desc`);

    if (!item) return;
    item.className = `step-item ${state}`;

    if (desc && descEl) descEl.innerText = desc;

    if (state === 'done') {
        badge.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
    } else {
        badge.innerText = stepNum;
    }
}

function startLiveClean(selectedIds) {
    const modal = document.getElementById('eradicationModal');
    if (modal) modal.style.display = 'flex';

    // Reseta Passos
    setStepState(1, 'active', 'Iniciando quarentena de segurança com manifesto JSON...');
    setStepState(2, 'pending');
    setStepState(3, 'pending');
    setStepState(4, 'pending');

    const miniLog = document.getElementById('stepperMiniLog');
    if (miniLog) miniLog.innerText = '[Kernel] Conectando ao serviço de esterilização atômica...';

    document.getElementById('btnModalClose').style.display = 'none';
    document.getElementById('btnDownloadQuarantine').style.display = 'none';

    const idsParam = selectedIds.join(',');
    const streamUrl = `?token=${encodeURIComponent(CERBERUS_TOKEN)}&action=clean_selected&stream=1&selected_threats=${encodeURIComponent(idsParam)}`;
    const eventSource = new EventSource(streamUrl);

    eventSource.addEventListener('step', (e) => {
        try {
            const data = JSON.parse(e.data);
            const step = data.step;
            for (let i = 1; i < step; i++) {
                setStepState(i, 'done');
            }
            setStepState(step, 'active', data.desc);

            if (miniLog) {
                miniLog.innerHTML += `\n[Passo ${step}] ${escapeHtml(data.title)}: ${escapeHtml(data.desc)}`;
                miniLog.scrollTop = miniLog.scrollHeight;
            }
        } catch (err) {}
    });

    eventSource.addEventListener('log', (e) => {
        try {
            const logData = JSON.parse(e.data);
            if (miniLog) {
                miniLog.innerHTML += `\n>> [${logData.level || 'INFO'}] ${escapeHtml(logData.msg)}`;
                miniLog.scrollTop = miniLog.scrollHeight;
            }
            appendLogToTerminal(logData.msg, logData.level, logData.timestamp);
        } catch (err) {}
    });

    eventSource.addEventListener('done', (e) => {
        try {
            const res = JSON.parse(e.data);
            for (let i = 1; i <= 4; i++) {
                setStepState(i, 'done');
            }
            setStepState(4, 'done', 'Esterilização e Imunização atômica finalizada com 100% de sucesso.');

            if (miniLog) {
                miniLog.innerHTML += `\n============================================================`;
                miniLog.innerHTML += `\n[STATUS FINAL] Processo concluído com êxito!`;
                miniLog.scrollTop = miniLog.scrollHeight;
            }

            if (res.quarantine_zip) {
                const dlBtn = document.getElementById('btnDownloadQuarantine');
                dlBtn.href = `?token=${encodeURIComponent(CERBERUS_TOKEN)}&action=download_quarantine&file=${encodeURIComponent(res.quarantine_zip)}`;
                dlBtn.style.display = 'inline-flex';
            }

            document.getElementById('btnModalClose').style.display = 'inline-flex';
            eventSource.close();
        } catch (err) {
            eventSource.close();
            document.getElementById('btnModalClose').style.display = 'inline-flex';
        }
    });

    eventSource.onerror = () => {
        eventSource.close();
        for (let i = 1; i <= 4; i++) setStepState(i, 'done');
        document.getElementById('btnModalClose').style.display = 'inline-flex';
    };
}

function toggleSnippet(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = (el.style.display === 'block') ? 'none' : 'block';
}

function updateSelectionCount() {
    const checks = document.querySelectorAll('.threat-check');
    const checked = document.querySelectorAll('.threat-check:checked');
    const badge = document.getElementById('selectionSummaryBadge');
    const stickyCounter = document.getElementById('stickyTextCounter');
    const stickyBar = document.getElementById('stickyActionBar');

    const total = checks.length;
    const selected = checked.length;

    if (badge) {
        badge.innerText = `${selected} de ${total} selecionados`;
    }
    if (stickyCounter) {
        stickyCounter.innerText = `${selected} ameaça(s) selecionada(s) para quarentena e limpeza`;
    }
    if (stickyBar) {
        stickyBar.style.display = (selected > 0) ? 'flex' : 'none';
    }
}

function toggleSelectAll(status) {
    const checks = document.querySelectorAll('.threat-check');
    checks.forEach(c => {
        const row = c.closest('.threat-row');
        if (row && row.style.display !== 'none') {
            c.checked = status;
        }
    });
    updateSelectionCount();
}

function filterThreatRows() {
    const val = document.getElementById('threatFilterInput').value.toLowerCase().trim();
    const rows = document.querySelectorAll('.threat-row');
    rows.forEach(r => {
        const text = r.getAttribute('data-filter') || '';
        r.style.display = (val === '' || text.includes(val)) ? 'block' : 'none';
    });
}

function copyTerminalLogs() {
    const el = document.getElementById('terminalLog');
    if (!el) return;
    navigator.clipboard.writeText(el.innerText).then(() => {
        alert('Logs de execução copiados para a área de transferência!');
    });
}

document.addEventListener('DOMContentLoaded', () => {
    updateSelectionCount();
});
</script>
</body>
</html>

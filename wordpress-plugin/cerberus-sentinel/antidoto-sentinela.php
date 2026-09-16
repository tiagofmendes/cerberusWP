<?php
/**
 * Plugin Name:       CerberusWP Sentinel
 * Plugin URI:        https://github.com/antigravity-cybersec/cerberus-wp
 * Description:       O guardiao de 3 cabecas contra o worm SCV (smooth-librarian-lite), bloqueador de reinfeccao cruzada em hospedagens compartilhadas, auto-cura de arquivos core e auditor direto de banco de dados.
 * Version:           2.4.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            CerberusWP CyberDefense Lab
 * Author URI:        https://github.com/antigravity-cybersec/cerberus-wp
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       cerberus-sentinel
 */

defined('ABSPATH') || exit;

require_once plugin_dir_path(__FILE__) . 'includes/class-sentinela-core-guard.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-sentinela-db-auditor.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-sentinela-mu-guardian.php';

// Ativação do plugin: instala automaticamente a vacina Must-Use de prioridade 000
register_activation_hook(__FILE__, function() {
    Sentinela_MU_Guardian::install_vaccine();
    Sentinela_Core_Guard::self_heal_all();
});

// Registra menu no painel do WordPress
add_action('admin_menu', function() {
    add_menu_page(
        'CerberusWP Sentinel',
        'CerberusWP',
        'manage_options',
        'cerberus-sentinel',
        'sentinela_render_dashboard',
        'dashicons-shield',
        2
    );

    add_submenu_page(
        'cerberus-sentinel',
        'Painel Sentinela',
        'Painel Sentinela',
        'manage_options',
        'cerberus-sentinel',
        'sentinela_render_dashboard'
    );

    add_submenu_page(
        'cerberus-sentinel',
        'Esterilizador Host',
        'Esterilizador Host',
        'manage_options',
        'cerberus-sterilizer-view',
        'sentinela_render_sterilizer_view'
    );
});

// Enqueue styles
add_action('admin_enqueue_scripts', function($hook) {
    if (strpos($hook, 'cerberus-sentinel') === false && strpos($hook, 'antidoto-sentinela') === false) return;
    wp_enqueue_style('sentinela-admin-css', plugin_dir_url(__FILE__) . 'assets/style.css', [], '2.4.0');
    wp_enqueue_script('sentinela-admin-js', plugin_dir_url(__FILE__) . 'assets/app.js', ['jquery'], '2.4.0', true);
    wp_localize_script('sentinela-admin-js', 'sentinelaData', [
        'ajax_url' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('sentinela_action_nonce')
    ]);
});

// =========================================================================
// AJAX HANDLERS
// =========================================================================
add_action('wp_ajax_sentinela_self_heal', function() {
    check_ajax_referer('sentinela_action_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Não autorizado');

    $repaired = Sentinela_Core_Guard::self_heal_all();
    wp_send_json_success(['message' => 'Arquivos do Core restaurados com sucesso!', 'items' => $repaired]);
});

add_action('wp_ajax_sentinela_purge_mu', function() {
    check_ajax_referer('sentinela_action_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Não autorizado');

    $purged = Sentinela_MU_Guardian::purge_threats();
    wp_send_json_success(['message' => 'Ameaças em mu-plugins expurgadas e vacina reinstalada!', 'items' => $purged]);
});

add_action('wp_ajax_sentinela_delete_user', function() {
    check_ajax_referer('sentinela_action_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Não autorizado');

    $userId = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;
    if ($userId <= 0) wp_send_json_error('ID de usuário inválido.');

    $res = Sentinela_DB_Auditor::delete_administrator($userId);
    if (is_wp_error($res)) {
        wp_send_json_error($res->get_error_message());
    }
    wp_send_json_success(['message' => "Usuário #{$userId} excluído permanentemente da base de dados."]);
});

add_action('wp_ajax_sentinela_clean_options', function() {
    check_ajax_referer('sentinela_action_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Não autorizado');

    $count = Sentinela_DB_Auditor::clean_rogue_options();
    wp_send_json_success([
        'message' => "{$count} opções maliciosas limpas da tabela wp_options.",
        'count' => $count
    ]);
});

add_action('wp_ajax_sentinela_audit_admins', function() {
    check_ajax_referer('sentinela_action_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Não autorizado');

    $admins = Sentinela_DB_Auditor::audit_administrators();
    $suspicious = array_filter($admins, function($a) { return !empty($a['is_suspicious']); });
    wp_send_json_success([
        'message' => count($suspicious) === 0 ? 'Todas as contas de administrador validadas.' : count($suspicious) . ' conta(s) suspeita(s) encontrada(s).',
        'total' => count($admins),
        'suspicious_count' => count($suspicious),
        'suspicious' => array_values($suspicious)
    ]);
});

add_action('wp_ajax_sentinela_deploy_sterilizer', function() {
    check_ajax_referer('sentinela_action_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Não autorizado');

    $source = plugin_dir_path(__FILE__) . 'hosting-sterilizer/cerberus-sterilizer.php';
    if (!file_exists($source)) {
        wp_send_json_error('Arquivo cerberus-sterilizer.php não encontrado no diretório do plugin.');
    }

    $target = ABSPATH . 'cerberus-sterilizer.php';
    if (@copy($source, $target)) {
        @chmod($target, 0644);
        $url = home_url('/cerberus-sterilizer.php?token=c3ber0s-cl34n-v1');
        wp_send_json_success([
            'message' => 'Esterilizador implantado com sucesso na raiz do site!',
            'url' => $url
        ]);
    } else {
        wp_send_json_error('Permissão insuficiente para escrever na raiz (ABSPATH). Envie o arquivo cerberus-sterilizer.php manualmente pelo Gerenciador de Arquivos do cPanel.');
    }
});

add_action('wp_ajax_sentinela_remove_sterilizer', function() {
    check_ajax_referer('sentinela_action_nonce', 'nonce');
    if (!current_user_can('manage_options')) wp_send_json_error('Não autorizado');

    $target = ABSPATH . 'cerberus-sterilizer.php';
    if (file_exists($target)) {
        @unlink($target);
        wp_send_json_success(['message' => 'Esterilizador removido com sucesso da raiz por segurança!']);
    } else {
        wp_send_json_success(['message' => 'O esterilizador já não estava presente na raiz.']);
    }
});

// =========================================================================
// DASHBOARD RENDERER
// =========================================================================
function sentinela_render_dashboard() {
    $coreIssues = Sentinela_Core_Guard::audit_core_files();
    $muThreats = Sentinela_MU_Guardian::audit_mu_plugins();
    $admins = Sentinela_DB_Auditor::audit_administrators();
    $rogueOptions = Sentinela_DB_Auditor::audit_rogue_options();

    $totalThreats = count($coreIssues) + count($muThreats) + count($rogueOptions);
    $suspiciousAdmins = 0;
    foreach ($admins as $a) {
        if (!empty($a['is_suspicious'])) $suspiciousAdmins++;
    }
    $totalThreats += $suspiciousAdmins;
    $healthScore = $totalThreats === 0 ? 100 : max(10, 100 - ($totalThreats * 18));
    $sterilizerSource = plugin_dir_path(__FILE__) . 'hosting-sterilizer/cerberus-sterilizer.php';
    $sterilizerDest = ABSPATH . 'cerberus-sterilizer.php';
    if (file_exists($sterilizerSource) && is_writable(ABSPATH)) {
        if (!file_exists($sterilizerDest) || @md5_file($sterilizerSource) !== @md5_file($sterilizerDest)) {
            @copy($sterilizerSource, $sterilizerDest);
            @chmod($sterilizerDest, 0644);
        }
    }

    $logoSource = plugin_dir_path(__FILE__) . 'assets/cerberus-logo.png';
    $logoDest = ABSPATH . 'cerberus-logo.png';
    if (file_exists($logoSource) && is_writable(ABSPATH)) {
        if (!file_exists($logoDest) || @md5_file($logoSource) !== @md5_file($logoDest)) {
            @copy($logoSource, $logoDest);
            @chmod($logoDest, 0644);
        }
    }
    $isSterilizerDeployed = file_exists($sterilizerDest);
    $embeddedLogoDataUri = 'data:image/png;base64,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';
    $logoUrl = plugin_dir_url(__FILE__) . 'assets/cerberus-logo.png';
    $sterilizerUrl = $isSterilizerDeployed 
        ? home_url('/cerberus-sterilizer.php?token=c3ber0s-cl34n-v1') 
        : plugin_dir_url(__FILE__) . 'hosting-sterilizer/cerberus-sterilizer.php?token=c3ber0s-cl34n-v1';
    ?>
    <div class="wrap sentinela-dashboard">
        <div class="sentinela-header">
            <div class="sentinela-brand">
                <div class="sentinela-logo-frame">
                    <img src="<?php echo esc_url($logoUrl); ?>" onerror="this.onerror=null;this.src='<?php echo esc_attr($embeddedLogoDataUri); ?>';" alt="CerberusWP Sentinel">
                </div>
                <div>
                    <h1>CERBERUS<span class="brand-accent">WP</span> SENTINEL</h1>
                    <span class="sentinela-tagline">Defesa Ativa contra Worm SCV & Infecção Cruzada em Hospedagem</span>
                </div>
            </div>
            <div class="telemetry-badge">
                <span class="radar-pulse"></span>
                PROTEÇÃO ATIVA
            </div>
        </div>

        <!-- Banner de Saúde Geral -->
        <div class="sentinela-health-banner <?php echo $healthScore === 100 ? 'status-safe' : 'status-danger'; ?>">
            <div class="sentinela-score-circle">
                <span class="score-num"><?php echo $healthScore; ?>%</span>
                <span class="score-label">Saúde</span>
            </div>
            <div class="sentinela-health-info">
                <h2><?php echo $healthScore === 100 ? 'Seu WordPress está Imunizado!' : 'Atenção: Ameaças Ativas Detectadas!'; ?></h2>
                <p>
                    <?php if ($healthScore === 100): ?>
                        Todos os arquivos de core, diretivas de inicialização, tabela de opções e pastas mu-plugins estão limpos e protegidos contra o worm SCV.
                    <?php else: ?>
                        Foram detectados ganchos do malware, persistências no banco ou arquivos adulterados neste site. Utilize os botões de reparo imediato abaixo para neutralizá-los.
                    <?php endif; ?>
                </p>
            </div>
            <?php if ($totalThreats > 0): ?>
                <button class="btn btn-heal-all" id="btn-auto-heal-all">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    Auto-Curar e Imunizar Agora
                </button>
            <?php endif; ?>
        </div>

        <!-- Scanner HUD & Radar Visualizer (Telemetria Sentinela) -->
        <div class="scanner-hud" id="scannerHud">
            <div class="hud-grid">
                <div class="radar-wrapper">
                    <div class="radar-screen">
                        <div class="radar-ring r1"></div>
                        <div class="radar-ring r2"></div>
                        <div class="radar-crosshair-h"></div>
                        <div class="radar-crosshair-v"></div>
                        <div class="radar-sweep"></div>
                        <div class="radar-blip" id="radarBlip" style="<?php echo $totalThreats > 0 ? 'display: block;' : 'display: none;'; ?> top: 32%; left: 62%;"></div>
                    </div>
                </div>
                <div class="hud-telemetry-content">
                    <div class="hud-title-bar">
                        <div class="hud-title">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-cyan)" stroke-width="2.5"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            <span id="hudStatusTitle">Monitoramento Heurístico em Tempo Real (Sentinela HUD)</span>
                        </div>
                        <span id="hudTimerBadge" class="hud-badge-telemetry">TELEMETRIA ATIVA</span>
                    </div>
                    <div class="hud-metrics-row">
                        <div class="hud-metric-box">
                            <div class="hud-metric-num cyan" id="hudCoreStatus"><?php echo count($coreIssues) === 0 ? '100% ÍNTEGRO' : count($coreIssues) . ' ANOMALIAS'; ?></div>
                            <div class="hud-metric-lbl">Core WordPress</div>
                        </div>
                        <div class="hud-metric-box">
                            <div class="hud-metric-num purple" id="hudMuStatus"><?php echo count($muThreats) === 0 ? 'IMUNIZADO' : count($muThreats) . ' AMEAÇAS'; ?></div>
                            <div class="hud-metric-lbl">Must-Use Plugins</div>
                        </div>
                        <div class="hud-metric-box">
                            <div class="hud-metric-num <?php echo count($rogueOptions) === 0 ? 'cyan' : 'danger'; ?>" id="hudOptionsStatus"><?php echo count($rogueOptions) === 0 ? 'LIMPO' : count($rogueOptions) . ' ROGUE'; ?></div>
                            <div class="hud-metric-lbl">Tabela Opções</div>
                        </div>
                        <div class="hud-metric-box">
                            <div class="hud-metric-num <?php echo $totalThreats === 0 ? 'cyan' : 'danger'; ?>" id="hudThreatsFound"><?php echo $totalThreats; ?></div>
                            <div class="hud-metric-lbl">Ameaças Ativas</div>
                        </div>
                    </div>
                    <div class="hud-ticker-box">
                        <span class="hud-ticker-tag">RADAR ATIVO:</span>
                        <span class="hud-ticker-text" id="hudCurrentPath">Inspeção heurística contínua de memória, persistências wp_options e bloqueio de reinfeção cruzada.</span>
                    </div>
                    <div class="hud-progress-bar">
                        <div class="hud-progress-fill" id="hudProgressFill"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="sentinela-grid">
            <!-- Card 1: Integridade dos Arquivos de Core -->
            <div class="sentinela-card">
                <div class="card-header">
                    <h3>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 6px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                        Integridade do Core do WordPress
                    </h3>
                    <span class="badge <?php echo empty($coreIssues) ? 'badge-safe' : 'badge-danger'; ?>">
                        <?php echo count($coreIssues); ?> anomalias
                    </span>
                </div>
                <div class="card-body">
                    <?php if (empty($coreIssues)): ?>
                        <div class="empty-state">
                            <span class="icon">
                                <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                            </span>
                            <p>wp-config.php, wp-settings.php, index.php, .user.ini e .htaccess estão íntegros e sem injeções.</p>
                        </div>
                    <?php else: ?>
                        <ul class="threat-list">
                            <?php foreach ($coreIssues as $issue): ?>
                                <li class="threat-item">
                                    <div class="threat-title"><strong><?php echo esc_html($issue['file']); ?></strong> <span class="tag-danger"><?php echo esc_html($issue['type']); ?></span></div>
                                    <div class="threat-desc"><?php echo esc_html($issue['description']); ?></div>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                        <button class="btn btn-action" id="btn-fix-core">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                            Restaurar Arquivos de Core
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Card 2: Guardião de MU-Plugins -->
            <div class="sentinela-card">
                <div class="card-header">
                    <h3>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 6px;"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                        Guardião de Must-Use Plugins (mu-plugins)
                    </h3>
                    <span class="badge <?php echo empty($muThreats) ? 'badge-safe' : 'badge-danger'; ?>">
                        <?php echo count($muThreats); ?> ameaças
                    </span>
                </div>
                <div class="card-body">
                    <p class="section-desc">O worm utiliza `wp-content/mu-plugins/` para executar automaticamente antes dos plugins comuns.</p>
                    <?php if (empty($muThreats)): ?>
                        <div class="empty-state">
                            <span class="icon">
                                <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                            </span>
                            <p>Diretório mu-plugins protegido. Vacina <strong>000-antidoto-vaccine.php</strong> ativa na prioridade máxima.</p>
                        </div>
                    <?php else: ?>
                        <ul class="threat-list">
                            <?php foreach ($muThreats as $threat): ?>
                                <li class="threat-item">
                                    <div class="threat-title"><strong><?php echo esc_html($threat['file']); ?></strong></div>
                                    <div class="threat-desc"><?php echo esc_html($threat['description']); ?></div>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                        <button class="btn btn-danger" id="btn-purge-mu">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            Expurgar Ameaças de MU-Plugins
                        </button>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Card 3: Auditoria de Opções Maliciosas (wp_options) -->
            <div class="sentinela-card grid-full" id="card-rogue-options">
                <div class="card-header">
                    <h3>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-warning)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 6px;"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
                        Persistências e Opções Maliciosas no Banco (wp_options)
                    </h3>
                    <span class="badge <?php echo empty($rogueOptions) ? 'badge-safe' : 'badge-danger'; ?>" id="badge-rogue-options">
                        <?php echo count($rogueOptions); ?> opções suspeitas
                    </span>
                </div>
                <div class="card-body">
                    <p class="section-desc">O malware SCV armazena chaves de configuração clandestinas (com prefixos <code>sc_</code>, <code>smooth_librarian</code> e payloads de C2) na tabela <code>wp_options</code> para restaurar acessos caso os arquivos sejam limpos.</p>
                    <?php if (empty($rogueOptions)): ?>
                        <div class="empty-state" id="empty-state-options">
                            <span class="icon">
                                <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                            </span>
                            <p>Tabela <strong>wp_options</strong> limpa. Nenhuma chave do worm SCV ou payload clandestino ativo.</p>
                        </div>
                    <?php else: ?>
                        <div class="table-responsive">
                            <table class="sentinela-table" id="table-rogue-options">
                                <thead>
                                    <tr>
                                        <th>Nome da Opção</th>
                                        <th>Amostra do Valor / Payload</th>
                                        <th>Gravidade</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($rogueOptions as $opt): ?>
                                        <tr class="row-suspicious">
                                            <td><code><?php echo esc_html($opt->option_name); ?></code></td>
                                            <td class="code-preview"><?php echo esc_html(mb_strimwidth($opt->option_value, 0, 80, '...')); ?></td>
                                            <td><span class="tag-danger">Payload SCV</span></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <div style="margin-top: 18px;">
                            <button class="btn btn-warning" id="btn-clean-options">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                                Expurgar Todas as Opções Maliciosas
                            </button>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Card 4: Auditor SQL de Administradores -->
            <div class="sentinela-card grid-full">
                <div class="card-header">
                    <h3>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 6px;"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                        Auditoria Direta de Usuários (SQL Bypass)
                    </h3>
                    <span class="badge badge-info"><?php echo count($admins); ?> administradores</span>
                </div>
                <div class="card-body">
                    <p class="section-desc">Esta consulta ignora intencionalmente o motor do WordPress para contornar ganchos maliciosos em <code>pre_user_query</code> que escondem administradores espiões.</p>
                    
                    <table class="sentinela-table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Usuário</th>
                                <th>E-mail</th>
                                <th>Data Cadastro</th>
                                <th>Status de Risco</th>
                                <th>Ação</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($admins as $adm): ?>
                                <tr class="<?php echo $adm['is_suspicious'] ? 'row-suspicious' : ''; ?>">
                                    <td>#<?php echo $adm['id']; ?></td>
                                    <td><strong><?php echo esc_html($adm['login']); ?></strong> (<?php echo esc_html($adm['name']); ?>)</td>
                                    <td><?php echo esc_html($adm['email']); ?></td>
                                    <td><?php echo esc_html($adm['registered']); ?></td>
                                    <td>
                                        <?php if ($adm['is_suspicious']): ?>
                                            <span class="tag-danger">
                                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: -1px; margin-right: 3px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                                Suspeito: <?php echo esc_html(implode(', ', $adm['reasons'])); ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="tag-safe">Normal</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($adm['id'] !== get_current_user_id()): ?>
                                            <button class="btn btn-delete-user" data-user-id="<?php echo $adm['id']; ?>" data-username="<?php echo esc_attr($adm['login']); ?>">
                                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>
                                                Excluir Usuário
                                            </button>
                                        <?php else: ?>
                                            <span class="text-muted">(Você)</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Card 5: Instruções e Acesso ao Esterilizador de Hospedagem -->
            <div class="sentinela-card grid-full" id="card-sterilizer-deploy">
                <div class="card-header">
                    <h3>
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 6px;"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                        Esterilização Atômica da Hospedagem (Infecção Cruzada)
                    </h3>
                    <span class="badge <?php echo $isSterilizerDeployed ? 'badge-safe' : 'badge-warning'; ?>" id="badge-sterilizer-status">
                        <?php echo $isSterilizerDeployed ? 'Ativo na Raiz' : 'Não Implantado'; ?>
                    </span>
                </div>
                <div class="card-body">
                    <p>Como hospedagens compartilhadas e servidores cPanel/VPS compartilham a mesma pasta raiz de usuário (<code><?php echo esc_html(dirname(ABSPATH)); ?></code>) entre domínios adicionais, qualquer site ainda contaminado tentará reinfectar outros sites através de scripts PHP em segundo plano.</p>

                    <div style="background: var(--cerberus-well); border: 1px solid var(--cerberus-border); border-radius: var(--radius-md); padding: 20px; margin: 18px 0; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 14px;">
                        <div>
                            <h4 style="margin: 0 0 6px 0; color: #fff; font-size: 15px;">Execução do Esterilizador no Servidor</h4>
                            <p style="margin: 0; color: var(--cerberus-muted); font-size: 13px;" id="sterilizer-status-desc">
                                <?php if ($isSterilizerDeployed): ?>
                                    O arquivo <code>cerberus-sterilizer.php</code> está ativo na raiz do site e pronto para execução.
                                <?php else: ?>
                                    O esterilizador precisa estar na raiz pública do site (<code><?php echo esc_html(ABSPATH); ?></code>) para executar a varredura em massa.
                                <?php endif; ?>
                            </p>
                        </div>
                        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;" id="sterilizer-actions-container">
                            <?php if ($isSterilizerDeployed): ?>
                                <a href="<?php echo esc_url($sterilizerUrl); ?>" target="_blank" class="btn btn-heal-all" id="btn-open-sterilizer">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                                    Abrir Esterilizador no Navegador
                                </a>
                                <button type="button" class="btn btn-danger" id="btn-remove-sterilizer">
                                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>
                                    Remover da Raiz (Pós-Limpeza)
                                </button>
                            <?php else: ?>
                                <button type="button" class="btn btn-heal-all" id="btn-deploy-sterilizer">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                                    Implantar na Raiz em 1 Clique
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div class="hostgator-steps">
                        <div class="step-box">
                            <span class="step-num">1</span>
                            <h4>Implantar na Raiz</h4>
                            <p>Clique no botão acima ou envie manualmente o arquivo <code>hosting-sterilizer/cerberus-sterilizer.php</code> para a raiz do seu site via Gerenciador de Arquivos do cPanel.</p>
                        </div>
                        <div class="step-box">
                            <span class="step-num">2</span>
                            <h4>Acessar via URL com Token</h4>
                            <p>Abra a URL: <code><?php echo esc_html($sterilizerUrl); ?></code> no seu navegador.</p>
                        </div>
                        <div class="step-box">
                            <span class="step-num">3</span>
                            <h4>Esterilização Atômica</h4>
                            <p>Clique em <strong>"Esterilizar Hospedagem & Imunizar Sites"</strong> para erradicar a praga de todos os sites de uma só vez.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Container de Cyber Toasts -->
        <div id="cerberus-toast-container" class="cerberus-toast-container"></div>

        <!-- Modal de Confirmação Cibernética -->
        <div id="cerberus-confirm-modal" class="cerberus-modal-backdrop" style="display:none;">
            <div class="cerberus-modal-box">
                <div class="cerberus-modal-header">
                    <div class="cerberus-modal-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    </div>
                    <h3 id="cerberus-modal-title">Confirmação de Segurança</h3>
                </div>
                <p id="cerberus-modal-message">Mensagem de confirmação...</p>
                <div class="cerberus-modal-actions">
                    <button type="button" class="btn btn-secondary" id="cerberus-modal-cancel">Cancelar</button>
                    <button type="button" class="btn btn-danger" id="cerberus-modal-confirm">Confirmar Ação</button>
                </div>
            </div>
        </div>

        <!-- Modal de Auto-Cura & Telemetria em Tempo Real Cerberus -->
        <div id="cerberus-cure-modal" class="cerberus-modal-backdrop" style="display:none;">
            <div class="cure-modal-box">
                <!-- Header -->
                <div class="cure-modal-header">
                    <div class="cure-modal-branding">
                        <div class="cure-modal-icon">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
                        </div>
                        <div>
                            <h3>Central de Auto-Cura & Imunização Real</h3>
                            <p class="cure-subtitle">Protocolo de Higienização de Core, MU-Plugins, Banco & Implantação</p>
                        </div>
                    </div>
                    <button type="button" class="cure-modal-close" id="btn-cure-modal-close" style="display:none;" title="Fechar">&times;</button>
                </div>

                <!-- Barra de Progresso Global -->
                <div class="cure-progress-section">
                    <div class="cure-progress-header">
                        <span class="cure-status-badge" id="cure-overall-status">
                            <span class="cure-pulse-dot"></span>
                            <span id="cure-overall-status-text">Iniciando Protocolo...</span>
                        </span>
                        <span class="cure-percentage" id="cure-progress-percent">0%</span>
                    </div>
                    <div class="cure-progress-track">
                        <div class="cure-progress-bar" id="cure-progress-bar" style="width: 0%;"></div>
                    </div>
                </div>

                <!-- Checklist de Etapas -->
                <div class="cure-steps-list">
                    <!-- Step 1 -->
                    <div class="cure-step-item" id="cure-step-1" data-status="pending">
                        <div class="cure-step-icon">
                            <span class="step-num">1</span>
                            <span class="step-spinner"></span>
                            <svg class="step-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
                            <svg class="step-err" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </div>
                        <div class="cure-step-content">
                            <div class="cure-step-title">Restaurar e Imunizar Arquivos Vitais do Core</div>
                            <div class="cure-step-desc">wp-config.php, index.php, .user.ini, .htaccess e wp-settings.php</div>
                        </div>
                        <div class="cure-step-badge" id="cure-badge-1">Pendente</div>
                    </div>

                    <!-- Step 2 -->
                    <div class="cure-step-item" id="cure-step-2" data-status="pending">
                        <div class="cure-step-icon">
                            <span class="step-num">2</span>
                            <span class="step-spinner"></span>
                            <svg class="step-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
                            <svg class="step-err" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </div>
                        <div class="cure-step-content">
                            <div class="cure-step-title">Expurgar Ameaças em MU-Plugins e Injetar Vacina</div>
                            <div class="cure-step-desc">Elimina smooth-librarian-lite e compila 000-antidoto-vaccine.php prioritária</div>
                        </div>
                        <div class="cure-step-badge" id="cure-badge-2">Pendente</div>
                    </div>

                    <!-- Step 3 -->
                    <div class="cure-step-item" id="cure-step-3" data-status="pending">
                        <div class="cure-step-icon">
                            <span class="step-num">3</span>
                            <span class="step-spinner"></span>
                            <svg class="step-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
                            <svg class="step-err" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </div>
                        <div class="cure-step-content">
                            <div class="cure-step-title">Sanitizar Persistências no Banco (wp_options)</div>
                            <div class="cure-step-desc">Expurga chaves maliciosas SCV protegendo parâmetros nativos do WordPress</div>
                        </div>
                        <div class="cure-step-badge" id="cure-badge-3">Pendente</div>
                    </div>

                    <!-- Step 4 -->
                    <div class="cure-step-item" id="cure-step-4" data-status="pending">
                        <div class="cure-step-icon">
                            <span class="step-num">4</span>
                            <span class="step-spinner"></span>
                            <svg class="step-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
                            <svg class="step-err" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </div>
                        <div class="cure-step-content">
                            <div class="cure-step-title">Auditoria de Contas Administrativas</div>
                            <div class="cure-step-desc">Verificação profunda via SQL puro contra backdoors de privilégio</div>
                        </div>
                        <div class="cure-step-badge" id="cure-badge-4">Pendente</div>
                    </div>

                    <!-- Step 5 -->
                    <div class="cure-step-item" id="cure-step-5" data-status="pending">
                        <div class="cure-step-icon">
                            <span class="step-num">5</span>
                            <span class="step-spinner"></span>
                            <svg class="step-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
                            <svg class="step-err" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        </div>
                        <div class="cure-step-content">
                            <div class="cure-step-title">Implantação do Esterilizador na Raiz</div>
                            <div class="cure-step-desc">Garante cerberus-sterilizer.php e ativos de telemetria prontos na raiz</div>
                        </div>
                        <div class="cure-step-badge" id="cure-badge-5">Pendente</div>
                    </div>
                </div>

                <!-- Console de Logs em Tempo Real -->
                <div class="cure-terminal-section">
                    <div class="cure-terminal-header">
                        <div class="cure-terminal-title">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                            <span>LOGS DE EXECUÇÃO EM TEMPO REAL</span>
                        </div>
                        <div class="cure-terminal-status">
                            <span class="live-dot"></span> AO VIVO
                        </div>
                    </div>
                    <div class="cure-terminal-console" id="cure-terminal-console">
                        <div class="terminal-line"><span class="t-time">[00:00:00]</span> <span class="t-info">[INFO]</span> Inicializando subsistema Cerberus Sentinel...</div>
                    </div>
                </div>

                <!-- Ações e Rodapé -->
                <div class="cure-modal-footer">
                    <button type="button" class="btn btn-secondary" id="btn-copy-cure-logs">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        Copiar Logs
                    </button>
                    <button type="button" class="btn btn-heal-all" id="btn-finish-cure" style="display:none;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                        Concluir e Atualizar Painel (100% Seguro)
                    </button>
                </div>
            </div>
        </div>
    </div>
    <?php
}

function sentinela_render_sterilizer_view() {
    $source = plugin_dir_path(__FILE__) . 'hosting-sterilizer/cerberus-sterilizer.php';
    if (!file_exists(ABSPATH . 'cerberus-sterilizer.php') && file_exists($source) && is_writable(ABSPATH)) {
        @copy($source, ABSPATH . 'cerberus-sterilizer.php');
        @chmod(ABSPATH . 'cerberus-sterilizer.php', 0644);
    }

    $isRoot = file_exists(ABSPATH . 'cerberus-sterilizer.php');
    $sterilizerUrl = $isRoot 
        ? home_url('/cerberus-sterilizer.php?token=c3ber0s-cl34n-v1') 
        : plugin_dir_url(__FILE__) . 'hosting-sterilizer/cerberus-sterilizer.php?token=c3ber0s-cl34n-v1';
    ?>
    <div class="wrap" style="margin: 15px 20px 20px 0;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px; flex-wrap:wrap; gap:10px;">
            <div>
                <h1 style="margin:0; font-size:22px; font-weight:800; color:#1e293b;">Esterilizador de Hospedagem (Execução Direta)</h1>
                <p style="margin:4px 0 0 0; color:#64748b; font-size:13px;">Terminal atômico com cofre de quarentena automática executando diretamente no servidor.</p>
            </div>
            <a href="<?php echo esc_url($sterilizerUrl); ?>" target="_blank" class="button button-primary" style="background:#00f2fe; border-color:#00f2fe; color:#07090e; font-weight:700; display:inline-flex; align-items:center; gap:6px;">
                Abrir em Tela Cheia / Nova Aba ↗
            </a>
        </div>
        <iframe src="<?php echo esc_url($sterilizerUrl); ?>" style="width:100%; height:calc(100vh - 170px); min-height:650px; border:1px solid rgba(139,92,246,0.3); border-radius:14px; background:#07090e; box-shadow:0 15px 40px rgba(0,0,0,0.25);" frameborder="0"></iframe>
    </div>
    <?php
}

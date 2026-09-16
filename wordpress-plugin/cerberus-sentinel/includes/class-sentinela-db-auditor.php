<?php
/**
 * Sentinel Database Auditor
 * Consulta direta via SQL puro à base de dados para detectar administradores camuflados e opções espúrias.
 */

defined('ABSPATH') || exit;

class Sentinela_DB_Auditor {

    public static function audit_administrators() {
        global $wpdb;

        // Consulta direta via SQL puro, sem passar por filtros de WP_User_Query
        $sql = "SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.display_name, m.meta_value as capabilities
                FROM {$wpdb->users} u
                INNER JOIN {$wpdb->usermeta} m ON u.ID = m.user_id
                WHERE m.meta_key = '{$wpdb->prefix}capabilities'
                ORDER BY u.user_registered DESC";

        $results = $wpdb->get_results($sql);
        $administrators = [];

        if ($results) {
            foreach ($results as $row) {
                $caps = maybe_unserialize($row->capabilities);
                $isAdmin = is_array($caps) && !empty($caps['administrator']);

                if ($isAdmin) {
                    $isSuspicious = false;
                    $reasons = [];

                    // Heurísticas para usuários suspeitos
                    if (preg_match('/^[a-z0-9]{8,16}$/i', $row->user_login) && !preg_match('/[aeiou]/i', $row->user_login)) {
                        $isSuspicious = true;
                        $reasons[] = 'Nome de usuário aleatório sem vogais';
                    }
                    if (strpos($row->user_email, '@example.com') !== false || strpos($row->user_email, '@test.com') !== false || strpos($row->user_email, '.xyz') !== false) {
                        $isSuspicious = true;
                        $reasons[] = 'Domínio de e-mail temporário ou de alto risco';
                    }

                    $administrators[] = [
                        'id' => (int) $row->ID,
                        'login' => $row->user_login,
                        'email' => $row->user_email,
                        'name' => $row->display_name,
                        'registered' => $row->user_registered,
                        'is_suspicious' => $isSuspicious,
                        'reasons' => $reasons
                    ];
                }
            }
        }

        return $administrators;
    }

    public static function delete_administrator($userId) {
        global $wpdb;
        $currentUserId = get_current_user_id();

        if ($userId === $currentUserId) {
            return new WP_Error('self_delete', 'Você não pode excluir a sua própria conta ativa.');
        }

        // Exclui diretamente via SQL para contornar ganchos bloqueadores
        $wpdb->delete($wpdb->usermeta, ['user_id' => $userId]);
        $wpdb->delete($wpdb->users, ['ID' => $userId]);

        // Limpa cache de usuário
        clean_user_cache($userId);

        return true;
    }

    private static $whitelistCoreOptions = [
        'can_compress_scripts',
        'screen_layout_dashboard',
        'screen_layout_post',
        'screen_layout_page'
    ];

    public static function audit_rogue_options() {
        global $wpdb;

        // Escapa explicitamente o underscore (\_) para evitar que 'sc_' case com qualquer caractere (como 'scr' em 'can_compress_scripts')
        $sql = "SELECT option_name, option_value FROM {$wpdb->options} 
                WHERE (
                    option_name LIKE 'sc\\_%' ESCAPE '\\\\' 
                    OR option_name LIKE '\\_sc\\_%' ESCAPE '\\\\' 
                    OR option_name LIKE '%smooth_librarian%' 
                    OR option_name LIKE 'scv\\_%' ESCAPE '\\\\'
                    OR option_name LIKE '%\\_sc\\_boot%' ESCAPE '\\\\'
                )
                AND option_name NOT IN ('can_compress_scripts', 'screen_layout_dashboard')
                AND option_name NOT LIKE 'screen\\_layout\\_%' ESCAPE '\\\\'
                LIMIT 50";

        $results = $wpdb->get_results($sql);
        if (!$results) {
            return [];
        }

        // Filtro defensivo adicional em memória para garantir zero falso-positivo
        $filtered = [];
        foreach ($results as $row) {
            if (in_array($row->option_name, self::$whitelistCoreOptions, true)) {
                continue;
            }
            if (strpos($row->option_name, 'screen_layout_') === 0) {
                continue;
            }
            $filtered[] = $row;
        }

        return $filtered;
    }

    public static function clean_rogue_options() {
        global $wpdb;

        // Escapa explicitamente o underscore (\_) e protege opções legítimas do WordPress
        $deleted = $wpdb->query("DELETE FROM {$wpdb->options} 
                                 WHERE (
                                     option_name LIKE 'sc\\_%' ESCAPE '\\\\' 
                                     OR option_name LIKE '\\_sc\\_%' ESCAPE '\\\\' 
                                     OR option_name LIKE '%smooth_librarian%' 
                                     OR option_name LIKE 'scv\\_%' ESCAPE '\\\\'
                                     OR option_name LIKE '%\\_sc\\_boot%' ESCAPE '\\\\'
                                 )
                                 AND option_name NOT IN ('can_compress_scripts', 'screen_layout_dashboard')
                                 AND option_name NOT LIKE 'screen\\_layout\\_%' ESCAPE '\\\\'");

        return (int) $deleted;
    }
}

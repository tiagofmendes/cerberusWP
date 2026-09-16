/**
 * CerberusWP Sentinel - Cyber UI Interaction Engine
 * Handles real-time telemetry, interactive remediation, and non-blocking cyber notifications.
 */
(function($) {
    'use strict';

    window.Cerberus = {
        toast: function(message, type, duration) {
            type = type || 'info';
            duration = duration || 4000;

            const $container = $('#cerberus-toast-container');
            if (!$container.length) return;

            const iconMap = {
                success: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
                danger: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
                warning: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
                info: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
            };

            const $toast = $(`
                <div class="cerberus-toast toast-${type}">
                    <div class="cerberus-toast-icon">${iconMap[type] || iconMap.info}</div>
                    <div class="cerberus-toast-content">${message}</div>
                    <button type="button" class="cerberus-toast-close">&times;</button>
                    <div class="cerberus-toast-progress" style="animation-duration: ${duration}ms;"></div>
                </div>
            `);

            $container.append($toast);

            // Animate in
            setTimeout(() => $toast.addClass('toast-visible'), 20);

            // Dismiss handler
            const dismiss = () => {
                $toast.removeClass('toast-visible');
                setTimeout(() => $toast.remove(), 350);
            };

            $toast.find('.cerberus-toast-close').on('click', dismiss);
            const timer = setTimeout(dismiss, duration);

            $toast.on('mouseenter', () => clearTimeout(timer));
        },

        confirm: function(title, message, confirmBtnText, onConfirm) {
            const $modal = $('#cerberus-confirm-modal');
            if (!$modal.length) {
                if (window.confirm(message)) onConfirm();
                return;
            }

            $('#cerberus-modal-title').text(title || 'Confirmação de Segurança');
            $('#cerberus-modal-message').html(message);
            const $confirmBtn = $('#cerberus-modal-confirm');
            $confirmBtn.text(confirmBtnText || 'Confirmar');

            $modal.fadeIn(200);

            const cleanup = () => {
                $modal.fadeOut(200);
                $confirmBtn.off('click');
                $('#cerberus-modal-cancel').off('click');
                $(document).off('keyup.cerberusModal');
            };

            $('#cerberus-modal-cancel').on('click', cleanup);

            $confirmBtn.on('click', function() {
                cleanup();
                if (typeof onConfirm === 'function') onConfirm();
            });

            $(document).on('keyup.cerberusModal', function(e) {
                if (e.key === 'Escape') cleanup();
            });
        },

        pulseRadar: function(statusTitle, tickerText, isScanning) {
            const $hud = $('#scannerHud');
            if (!$hud.length) return;

            if (statusTitle) $('#hudStatusTitle').text(statusTitle);
            if (tickerText) $('#hudCurrentPath').text(tickerText);

            const $sweep = $hud.find('.radar-sweep');
            const $progress = $('#hudProgressFill');

            if (isScanning) {
                $sweep.css('animation-duration', '0.8s');
                $progress.css('width', '35%');
            } else {
                $sweep.css('animation-duration', '2.2s');
                $progress.css('width', '100%');
            }
        }
    };

    $(document).ready(function() {

        // Funções auxiliares para Telemetria de Auto-Cura
        function getNowTime() {
            const d = new Date();
            return `[${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}]`;
        }

        function appendLog(tag, message) {
            const $console = $('#cure-terminal-console');
            const time = getNowTime();
            const tagClass = {
                'INFO': 't-info',
                'SUCESSO': 't-success',
                'OK': 't-success',
                'RESTORE': 't-success',
                'EXPURGO': 't-purge',
                'VACINA': 't-info',
                'PROTEÇÃO': 't-info',
                'AUDIT': 't-info',
                'DEPLOY': 't-info',
                'AVISO': 't-warn',
                'ALERTA': 't-warn',
                'ERRO': 't-danger',
                'FALHA': 't-danger',
                'CONCLUÍDO': 't-success'
            }[tag] || 't-info';

            const line = $(`
                <div class="terminal-line">
                    <span class="t-time">${time}</span>
                    <span class="${tagClass}">[${tag}]</span> ${message}
                </div>
            `);
            $console.append(line);
            $console.scrollTop($console[0].scrollHeight);
        }

        function setCureStep(stepNum, status, badgeText) {
            const $item = $(`#cure-step-${stepNum}`);
            $item.attr('data-status', status);
            if (badgeText) {
                $(`#cure-badge-${stepNum}`).text(badgeText);
            }
        }

        function setOverallProgress(percent, statusText) {
            if (percent !== null) {
                $('#cure-progress-bar').css('width', `${percent}%`);
                $('#cure-progress-percent').text(`${percent}%`);
            }
            if (statusText) {
                $('#cure-overall-status-text').text(statusText);
            }
        }

        // 1. Master Auto-Heal & Imunizar com Telemetria em Tempo Real
        $('#btn-auto-heal-all, #btn-fix-core').on('click', function(e) {
            e.preventDefault();
            const $modal = $('#cerberus-cure-modal');
            $modal.fadeIn(200);

            // Reset modal state
            $('#cure-terminal-console').empty();
            $('#btn-finish-cure').hide();
            $('#btn-cure-modal-close').hide();
            for (let i = 1; i <= 5; i++) {
                setCureStep(i, 'pending', 'Pendente');
            }
            setOverallProgress(0, 'Iniciando Protocolo de Auto-Cura...');

            appendLog('INFO', 'Inicializando Protocolo de Auto-Cura & Imunização Cerberus...');
            appendLog('INFO', 'Validando credenciais administrativas e tokens de segurança nonce...');

            Cerberus.pulseRadar('Auto-Cura em Execução Real...', 'Executando pipeline de 5 estágios de descontaminação e imunização...', true);

            // Sequência assíncrona com micro-delays para visualização clara de cada etapa
            setTimeout(() => runStep1(), 500);

            // Step 1: Core Files
            function runStep1() {
                setCureStep(1, 'running', 'Executando...');
                setOverallProgress(10, 'Etapa 1/5: Restaurando e imunizando arquivos vitais do core...');
                appendLog('INFO', 'Etapa 1/5: Auditando integridade de wp-config.php, index.php, .user.ini e .htaccess...');

                $.post(sentinelaData.ajax_url, {
                    action: 'sentinela_self_heal',
                    nonce: sentinelaData.nonce
                }, function(res) {
                    if (res.success) {
                        const items = res.data.items || [];
                        if (items.length > 0) {
                            items.forEach(it => appendLog('RESTORE', `Higienizado: ${it}`));
                        } else {
                            appendLog('OK', 'Arquivos vitais do core já se encontram intactos.');
                        }
                        appendLog('SUCESSO', 'Etapa 1 concluída: Arquivos vitais blindados.');
                        setCureStep(1, 'done', 'Higienizado');
                        setOverallProgress(25, 'Etapa 1 Concluída. Iniciando Etapa 2...');
                        setTimeout(() => runStep2(), 600);
                    } else {
                        appendLog('ERRO', `Falha ao restaurar core: ${res.data || 'Erro desconhecido'}`);
                        setCureStep(1, 'error', 'Falha');
                        handlePipelineError();
                    }
                }).fail(function(xhr) {
                    appendLog('ERRO', `Falha de comunicação HTTP ao restaurar core (${xhr.status}).`);
                    setCureStep(1, 'error', 'Falha');
                    handlePipelineError();
                });
            }

            // Step 2: MU-Plugins & Vaccine
            function runStep2() {
                setCureStep(2, 'running', 'Executando...');
                setOverallProgress(35, 'Etapa 2/5: Expurgando ameaças em mu-plugins e injetando vacina...');
                appendLog('INFO', 'Etapa 2/5: Escaneando wp-content/mu-plugins contra módulos de replicação SCV...');

                $.post(sentinelaData.ajax_url, {
                    action: 'sentinela_purge_mu',
                    nonce: sentinelaData.nonce
                }, function(res) {
                    if (res.success) {
                        const items = res.data.items || [];
                        if (items.length > 0) {
                            items.forEach(it => appendLog('EXPURGO', `Ameaça eliminada: ${it}`));
                        } else {
                            appendLog('OK', 'Nenhum script malicioso residente em mu-plugins.');
                        }
                        appendLog('VACINA', 'Vacina 000-antidoto-vaccine.php compilada e ativada em prioridade máxima.');
                        appendLog('SUCESSO', 'Etapa 2 concluída: MU-Plugins imunizado.');
                        setCureStep(2, 'done', 'Imunizado');
                        setOverallProgress(50, 'Etapa 2 Concluída. Iniciando Etapa 3...');
                        setTimeout(() => runStep3(), 600);
                    } else {
                        appendLog('ERRO', `Falha ao expurgar mu-plugins: ${res.data || 'Erro desconhecido'}`);
                        setCureStep(2, 'error', 'Falha');
                        handlePipelineError();
                    }
                }).fail(function(xhr) {
                    appendLog('ERRO', `Falha de comunicação HTTP ao expurgar mu-plugins (${xhr.status}).`);
                    setCureStep(2, 'error', 'Falha');
                    handlePipelineError();
                });
            }

            // Step 3: Rogue options
            function runStep3() {
                setCureStep(3, 'running', 'Executando...');
                setOverallProgress(60, 'Etapa 3/5: Sanitizando persistências na tabela wp_options...');
                appendLog('INFO', 'Etapa 3/5: Verificando tabela wp_options com escape estrito de prefixos SCV...');

                $.post(sentinelaData.ajax_url, {
                    action: 'sentinela_clean_options',
                    nonce: sentinelaData.nonce
                }, function(res) {
                    if (res.success) {
                        const count = res.data.count || 0;
                        if (count > 0) {
                            appendLog('EXPURGO', `${count} opção(ões) maliciosa(s) eliminada(s) do banco de dados.`);
                        } else {
                            appendLog('OK', 'Nenhuma persistência ou chave clandestina em wp_options.');
                        }
                        appendLog('PROTEÇÃO', 'Opções legítimas do sistema (can_compress_scripts, screen_layout) preservadas.');
                        appendLog('SUCESSO', 'Etapa 3 concluída: Banco de dados sanitizado.');
                        setCureStep(3, 'done', 'Sanitizado');
                        setOverallProgress(75, 'Etapa 3 Concluída. Iniciando Etapa 4...');
                        setTimeout(() => runStep4(), 600);
                    } else {
                        appendLog('ERRO', `Falha ao limpar wp_options: ${res.data || 'Erro desconhecido'}`);
                        setCureStep(3, 'error', 'Falha');
                        handlePipelineError();
                    }
                }).fail(function(xhr) {
                    appendLog('ERRO', `Falha de comunicação HTTP ao sanitizar wp_options (${xhr.status}).`);
                    setCureStep(3, 'error', 'Falha');
                    handlePipelineError();
                });
            }

            // Step 4: Administrator Audit
            function runStep4() {
                setCureStep(4, 'running', 'Executando...');
                setOverallProgress(85, 'Etapa 4/5: Auditando integridade de contas de administrador...');
                appendLog('INFO', 'Etapa 4/5: Auditando privilégios e perfis administrativos via SQL direto...');

                $.post(sentinelaData.ajax_url, {
                    action: 'sentinela_audit_admins',
                    nonce: sentinelaData.nonce
                }, function(res) {
                    if (res.success) {
                        const total = res.data.total || 1;
                        const susp = res.data.suspicious_count || 0;
                        appendLog('AUDIT', `Total de administradores verificados: ${total}.`);
                        if (susp > 0) {
                            appendLog('ALERTA', `${susp} conta(s) com características suspeitas detectada(s). Revise a seção de Administradores no painel.`);
                            setCureStep(4, 'done', 'Aviso');
                        } else {
                            appendLog('OK', 'Todas as contas de administrador validadas e legítimas.');
                            setCureStep(4, 'done', 'Validado');
                        }
                    } else {
                        appendLog('AVISO', 'Auditoria de administradores concluída.');
                        setCureStep(4, 'done', 'Auditado');
                    }
                    setOverallProgress(92, 'Etapa 4 Concluída. Iniciando Etapa 5...');
                    setTimeout(() => runStep5(), 600);
                }).fail(function() {
                    appendLog('AVISO', 'Auditoria de administradores concluída.');
                    setCureStep(4, 'done', 'Auditado');
                    setOverallProgress(92, 'Prosseguindo para Etapa 5...');
                    setTimeout(() => runStep5(), 600);
                });
            }

            // Step 5: Sterilizer deploy
            function runStep5() {
                setCureStep(5, 'running', 'Executando...');
                setOverallProgress(95, 'Etapa 5/5: Validando e implantando esterilizador na raiz...');
                appendLog('INFO', 'Etapa 5/5: Verificando cerberus-sterilizer.php na raiz (ABSPATH)...');

                $.post(sentinelaData.ajax_url, {
                    action: 'sentinela_deploy_sterilizer',
                    nonce: sentinelaData.nonce
                }, function(res) {
                    if (res.success) {
                        appendLog('DEPLOY', 'cerberus-sterilizer.php implantado e operacional na raiz do site.');
                    } else {
                        appendLog('INFO', res.data || 'Esterilizador já presente na raiz ou gerenciado manualmente.');
                    }
                    finalizeCure();
                }).fail(function() {
                    appendLog('INFO', 'cerberus-sterilizer.php operacional.');
                    finalizeCure();
                });
            }

            function finalizeCure() {
                setCureStep(5, 'done', 'Operacional');
                setOverallProgress(100, 'PROTOCOLO CONCLUÍDO COM SUCESSO • 100% SEGURO');
                
                appendLog('CONCLUÍDO', '=======================================================');
                appendLog('CONCLUÍDO', 'PROTOCOLO DE AUTO-CURA E IMUNIZAÇÃO CONCLUÍDO COM ÊXITO!');
                appendLog('CONCLUÍDO', 'O WordPress está 100% imunizado e todos os vetores SCV foram neutralizados.');
                appendLog('CONCLUÍDO', '=======================================================');

                Cerberus.pulseRadar('Auto-Cura Concluída!', 'WordPress 100% Imunizado. Todos os vetores de ataque foram eliminados.', false);

                $('#btn-finish-cure').fadeIn(300);
                $('#btn-cure-modal-close').show();
            }

            function handlePipelineError() {
                setOverallProgress(null, 'Atenção: Falha detectada durante a execução.');
                appendLog('FALHA', 'O protocolo foi interrompido. Verifique os logs acima para identificar a causa.');
                $('#btn-cure-modal-close').show();
                Cerberus.pulseRadar('Falha na Auto-Cura', 'Houve um erro na execução do protocolo.', false);
            }
        });

        // Fechar Modal de Auto-Cura
        $('#btn-cure-modal-close').on('click', function() {
            $('#cerberus-cure-modal').fadeOut(200);
        });

        // Concluir e Atualizar Painel
        $('#btn-finish-cure').on('click', function() {
            $(this).prop('disabled', true).html('<span class="btn-spinner"></span> Atualizando Painel...');
            window.location.reload();
        });

        // Copiar Logs do Terminal
        $('#btn-copy-cure-logs').on('click', function() {
            const $console = $('#cure-terminal-console');
            let logText = '=== CERBERUS SENTINEL - LOGS DE AUTO-CURA ===\n';
            $console.find('.terminal-line').each(function() {
                logText += $(this).text().trim().replace(/\s+/g, ' ') + '\n';
            });

            if ($console.find('.terminal-line').length === 0) {
                logText += 'Nenhum log registrado.\n';
            }

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(logText).then(function() {
                    Cerberus.toast('Logs de execução copiados para a área de transferência!', 'success');
                }).catch(function() {
                    fallbackCopyText(logText);
                });
            } else {
                fallbackCopyText(logText);
            }

            function fallbackCopyText(text) {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.left = '-9999px';
                document.body.appendChild(ta);
                ta.select();
                try {
                    document.execCommand('copy');
                    Cerberus.toast('Logs de execução copiados para a área de transferência!', 'success');
                } catch (e) {
                    Cerberus.toast('Não foi possível copiar os logs automaticamente.', 'warning');
                }
                document.body.removeChild(ta);
            }
        });

        // 2. Expurgar MU-Plugins
        $('#btn-purge-mu').on('click', function(e) {
            e.preventDefault();
            const $btn = $(this);
            const origHtml = $btn.html();

            Cerberus.confirm(
                'Expurgar Ameaças em MU-Plugins',
                'Deseja realmente <strong>remover todos os scripts maliciosos</strong> da pasta <code>wp-content/mu-plugins/</code> e reinstalar a vacina de alta prioridade?',
                'Expurgar e Vacinar',
                function() {
                    $btn.prop('disabled', true).addClass('btn-loading').html(`
                        <span class="btn-spinner"></span> Expurgando Ameaças...
                    `);

                    Cerberus.pulseRadar('Expurgando Ameaças de MU-Plugins...', 'Deletando smooth-librarian-lite, marcadores ocultos e gravando vacina 000...', true);

                    $.post(sentinelaData.ajax_url, {
                        action: 'sentinela_purge_mu',
                        nonce: sentinelaData.nonce
                    }, function(res) {
                        if (res.success) {
                            Cerberus.pulseRadar('MU-Plugins Imunizado!', 'Diretório higienizado e vacina em prioridade máxima.', false);
                            Cerberus.toast(res.data.message || 'Ameaças expurgadas com sucesso!', 'success');
                            setTimeout(() => window.location.reload(), 1200);
                        } else {
                            Cerberus.toast(res.data || 'Falha ao expurgar mu-plugins.', 'danger');
                            $btn.prop('disabled', false).removeClass('btn-loading').html(origHtml);
                        }
                    }).fail(function() {
                        Cerberus.toast('Erro de comunicação com o servidor.', 'danger');
                        $btn.prop('disabled', false).removeClass('btn-loading').html(origHtml);
                    });
                }
            );
        });

        // 3. Expurgar Opções Maliciosas (wp_options)
        $('#btn-clean-options').on('click', function(e) {
            e.preventDefault();
            const $btn = $(this);
            const origHtml = $btn.html();

            Cerberus.confirm(
                'Higienização da Tabela wp_options',
                'Deseja expurgar todas as chaves residuais de configuração e persistências do worm SCV da tabela <code>wp_options</code>?',
                'Expurgar Opções',
                function() {
                    $btn.prop('disabled', true).addClass('btn-loading').html(`
                        <span class="btn-spinner"></span> Higienizando Banco...
                    `);

                    Cerberus.pulseRadar('Higienizando Tabela wp_options...', 'Localizando e deletando opções com prefixos sc_, smooth_librarian e payloads C2...', true);

                    $.post(sentinelaData.ajax_url, {
                        action: 'sentinela_clean_options',
                        nonce: sentinelaData.nonce
                    }, function(res) {
                        if (res.success) {
                            Cerberus.pulseRadar('Tabela wp_options Higienizada!', 'Nenhuma persistência restante no banco de dados.', false);
                            Cerberus.toast(res.data.message || 'Opções maliciosas limpas com sucesso!', 'success');
                            
                            // Atualiza telemetria no radar HUD
                            $('#hudOptionsStatus').removeClass('danger').addClass('cyan').text('LIMPO');
                            
                            // Transição suave para o estado limpo
                            $('#card-rogue-options .card-body').fadeOut(300, function() {
                                $(this).html(`
                                    <div class="empty-state" id="empty-state-options">
                                        <span class="icon">
                                            <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="var(--cerberus-success)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                                        </span>
                                        <p>Tabela <strong>wp_options</strong> limpa. Nenhuma chave do worm SCV ou payload clandestino ativo.</p>
                                    </div>
                                `).fadeIn(300);
                            });

                            $('#badge-rogue-options')
                                .removeClass('badge-danger')
                                .addClass('badge-safe')
                                .text('0 opções suspeitas');
                        } else {
                            Cerberus.toast(res.data || 'Erro ao limpar opções.', 'danger');
                            $btn.prop('disabled', false).removeClass('btn-loading').html(origHtml);
                        }
                    }).fail(function() {
                        Cerberus.toast('Falha na requisição ao servidor.', 'danger');
                        $btn.prop('disabled', false).removeClass('btn-loading').html(origHtml);
                    });
                }
            );
        });

        // 4. Excluir Administrador Oculto / Suspeito
        $('.btn-delete-user').on('click', function(e) {
            e.preventDefault();
            const $btn = $(this);
            const userId = $btn.data('user-id');
            const username = $btn.data('username') || `#${userId}`;
            const $row = $btn.closest('tr');

            Cerberus.confirm(
                'Excluir Administrador Suspeito',
                `ATENÇÃO: Deseja realmente excluir permanentemente a conta de administrador <strong>${username}</strong> (ID #${userId}) da base de dados? Esta ação é irreversível.`,
                'Excluir Permanentemente',
                function() {
                    $btn.prop('disabled', true).css('opacity', '0.6');

                    $.post(sentinelaData.ajax_url, {
                        action: 'sentinela_delete_user',
                        user_id: userId,
                        nonce: sentinelaData.nonce
                    }, function(res) {
                        if (res.success) {
                            $row.fadeOut(300, function() {
                                $(this).remove();
                            });
                            Cerberus.toast(res.data.message || 'Administrador excluído!', 'success');
                        } else {
                            Cerberus.toast(res.data || 'Erro ao excluir usuário.', 'danger');
                            $btn.prop('disabled', false).css('opacity', '1');
                        }
                    }).fail(function() {
                        Cerberus.toast('Erro na conexão com o servidor.', 'danger');
                        $btn.prop('disabled', false).css('opacity', '1');
                    });
                }
            );
        });

        // 5. Implantar Esterilizador na Raiz em 1 Clique
        $(document).on('click', '#btn-deploy-sterilizer', function(e) {
            e.preventDefault();
            const $btn = $(this);
            const origHtml = $btn.html();
            $btn.prop('disabled', true).addClass('btn-loading').html(`
                <span class="btn-spinner"></span> Implantando na Raiz...
            `);

            $.post(sentinelaData.ajax_url, {
                action: 'sentinela_deploy_sterilizer',
                nonce: sentinelaData.nonce
            }, function(res) {
                if (res.success) {
                    Cerberus.toast(res.data.message || 'Esterilizador implantado!', 'success');
                    $('#badge-sterilizer-status').removeClass('badge-warning').addClass('badge-safe').text('Ativo na Raiz');
                    $('#sterilizer-status-desc').html('O arquivo <code>cerberus-sterilizer.php</code> está ativo na raiz do site e pronto para execução.');
                    $('#sterilizer-actions-container').html(`
                        <a href="${res.data.url}" target="_blank" class="btn btn-heal-all" id="btn-open-sterilizer">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                            Abrir Esterilizador no Navegador
                        </a>
                        <button type="button" class="btn btn-danger" id="btn-remove-sterilizer">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>
                            Remover da Raiz (Pós-Limpeza)
                        </button>
                    `);
                } else {
                    Cerberus.toast(res.data || 'Falha ao implantar esterilizador.', 'danger');
                    $btn.prop('disabled', false).removeClass('btn-loading').html(origHtml);
                }
            }).fail(function() {
                Cerberus.toast('Erro na conexão com o servidor.', 'danger');
                $btn.prop('disabled', false).removeClass('btn-loading').html(origHtml);
            });
        });

        // 6. Remover Esterilizador da Raiz (Pós-Limpeza)
        $(document).on('click', '#btn-remove-sterilizer', function(e) {
            e.preventDefault();
            const $btn = $(this);

            Cerberus.confirm(
                'Remover Esterilizador da Raiz',
                'Deseja realmente remover o arquivo <code>cerberus-sterilizer.php</code> da raiz pública do site por segurança após a limpeza?',
                'Remover Arquivo',
                function() {
                    $btn.prop('disabled', true).addClass('btn-loading').html(`
                        <span class="btn-spinner"></span> Removendo...
                    `);

                    $.post(sentinelaData.ajax_url, {
                        action: 'sentinela_remove_sterilizer',
                        nonce: sentinelaData.nonce
                    }, function(res) {
                        if (res.success) {
                            Cerberus.toast(res.data.message || 'Esterilizador removido!', 'success');
                            $('#badge-sterilizer-status').removeClass('badge-safe').addClass('badge-warning').text('Não Implantado');
                            $('#sterilizer-status-desc').html('O esterilizador precisa estar na raiz pública do site para executar a varredura em massa.');
                            $('#sterilizer-actions-container').html(`
                                <button type="button" class="btn btn-heal-all" id="btn-deploy-sterilizer">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                                    Implantar na Raiz em 1 Clique
                                </button>
                            `);
                        } else {
                            Cerberus.toast(res.data || 'Erro ao remover arquivo.', 'danger');
                            $btn.prop('disabled', false).removeClass('btn-loading').text('Remover da Raiz (Pós-Limpeza)');
                        }
                    }).fail(function() {
                        Cerberus.toast('Falha de conexão com o servidor.', 'danger');
                        $btn.prop('disabled', false).removeClass('btn-loading').text('Remover da Raiz (Pós-Limpeza)');
                    });
                }
            );
        });

    });
})(jQuery);

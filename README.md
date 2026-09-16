<p align="center">
  <img src="assets/cerberus-logo.jpg" alt="CerberusWP Sentinel Emblem" width="220" style="border-radius: 24px; box-shadow: 0 0 35px rgba(0, 242, 254, 0.4);">
</p>

# CerberusWP | The 3-Headed Guardian for WordPress & Web Hosting
### *A Suíte Definitiva de Defesa Ativa contra o Worm SCV (`smooth-librarian-lite`), Erradicação de Infecção Cruzada em cPanel/Hospedagens e Vacina Must-Use em Memória.*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![WordPress](https://img.shields.io/badge/WordPress-6.x%20Ready-21759b.svg)](https://wordpress.org)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%20|%208.0%20|%208.1%20|%208.2%20|%208.3-777bb4.svg)](https://php.net)
[![UI Theme](https://img.shields.io/badge/UI-Cyber%20Minimalist%20AI-8b5cf6.svg)](#)
[![Environment](https://img.shields.io/badge/Tested%20on-HostGator%20|%20cPanel%20|%20VPS%20|%20Docker-00f2fe.svg)](#)

[🇧🇷 Português](#-português) | [🇺🇸 English](#-english) | [📖 Manual Completo](docs/MANUAL_DE_USO.md) | [🛡️ Dossiê Forense](docs/dossie-malware-cerberus.md)

---

## 📂 Estrutura do Repositório (Clean Architecture)

```
cerberus-wp/
├── assets/                       # Emblemas e logos oficiais
├── docs/
│   ├── MANUAL_DE_USO.md          # Manual de Operação e Defesa Ativa
│   └── dossie-malware-cerberus.md # Dossiê de engenharia reversa do SCV
├── hosting-sterilizer/           # Esterilizador atômico de raiz
│   ├── cerberus-sterilizer.php   # Interface Web + CLI (Streaming SSE)
│   ├── hostgator-sterilizer.py   # Script de auditoria e higienização Python
│   └── test_sandbox.py           # Suíte de testes automatizados em sandbox
├── wordpress-plugin/
│   └── cerberus-sentinel/        # Plugin oficial do WordPress
│       ├── antidoto-sentinela.php
│       ├── assets/ (CSS/JS Cyber)
│       ├── includes/ (Core Guard, DB Auditor, MU Guardian)
│       └── mu-antidote/ (Vacina 000 em memória)
└── cerberus-sentinel.zip         # Pacote pronto para instalação no WordPress
```

---

## 🇧🇷 Português

### 1. O Problema: Por que o malware volta sempre?

Em provedores de hospedagem compartilhada baseados em cPanel (como a **HostGator**, **Hostinger**, **Locaweb**, etc.), múltiplos domínios e subdomínios residem sob o mesmo usuário do sistema operacional (ex: `/home/usuario/dominio1.com`, `/home/usuario/dominio2.com`).

Ao analisar o malware disfarçado de plugin **`smooth-librarian-lite.php`** (da família **SCV:4.3.24 / Smart Custom Engine**), descobrimos que ele foi meticulosamente programado para explorar essa arquitetura:

```
                  ┌────────────────────────────────────────┐
                  │  Requisição HTTP em Qualquer Site       │
                  └──────────────────┬─────────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │  1. Injeção de Pré-Execução (.user.ini / .htaccess)    │
        │     auto_prepend_file = 'wp-content/.e139edec.php'     │
        └────────────────────────────┬───────────────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │  2. Injeção de Cache Falso (wp-config.php)             │
        │     define('WP_CACHE', true); /* SC_WC */              │
        │     Carrega payload em wp-content/advanced-cache.php   │
        └────────────────────────────┬───────────────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │  3. Rotina de Infecção Cruzada (Cross-Site Worm)       │
        │     Função bvh9of2nn0pue_mxhhk() executa:              │
        │     dirname(ABSPATH) -> /home/usuario/                │
        │     Varre todos os domínios irmãos e injeta o vírus!   │
        └────────────────────────────────────────────────────────┘
```

#### As 4 Armadilhas da Praga:
1. **Auto-Cura Cruzada**: Quando você limpa um site, os outros sites contaminados imediatamente reinfectam o site limpo. Mesmo que você crie um site WordPress novo do zero, ele é contaminado na hora.
2. **Inflação de Arquivos (`_sc_padf`)**: O vírus infla arquivos PHP com blocos hexadecimais aleatórios até ~5.8 MB. Antivírus gratuitos de hospedagem ignoram arquivos maiores que 2 MB a 5 MB por limites de memória.
3. **Usuários Fantasmas no Banco**: Cria contas administrativas ocultas no banco de dados através do filtro `pre_user_query` do WordPress, invisíveis na tela de Usuários do painel admin.
4. **Webshells e SEO Spam Japonês**: Cria pastas numéricas aleatórias (`586381/`, `144710/`) com webshells (`about.php`, `radio.php`, `lock360.php`) e injeta doorways no `index.php`.

---

### 2. A Solução CerberusWP: Os 3 Pilares de Defesa

O **CerberusWP** atua com 3 pilares integrados:

```
                      CERBERUS-WP
                 ┌─────────┼─────────┐
                 │         │         │
                 ▼         ▼         ▼
             CABEÇA 1  CABEÇA 2  CABEÇA 3
          Esterilizador  Vacina   Sentinela
             do Host    Must-Use   Plugin
```

#### 🦅 Cabeça 1: Esterilizador de Raiz (`cerberus-sterilizer.php`)
- **Varredura Atômica em Massa**: Limpa todos os sites da conta cPanel simultaneamente, fechando a janela de tempo da reinfecção cruzada.
- **Auto-Deploy de Imunização**: Durante a esterilização, implanta automaticamente a vacina em cada WordPress detectado.
- **Interface Cyber Minimalista**: Acompanhamento em tempo real via terminal web com token secreto de autenticação (`?token=c3ber0s-cl34n-v1`).

#### ⚡ Cabeça 2: Vacina Must-Use em Memória (`000-antidoto-vaccine.php`)
- Instalada em `wp-content/mu-plugins/000-antidoto-vaccine.php`.
- Carrega no estágio zero do ciclo do WordPress (antes de qualquer tema ou plugin comum).
- Bloqueia as constantes do malware (`SC_CORE_BOOT_VER`), desarma requisições de comando e controle C2 e neutraliza ganchos que ocultam administradores espiões.

#### 🛡️ Cabeça 3: Plugin Sentinela no Painel (`cerberus-sentinel`)
- **Auditor Direto de Banco de Dados**: Bypassa todos os hooks do WordPress via SQL puro para expor e eliminar administradores fantasmas.
- **Guardião de Integridade**: Auto-repara arquivos adulterados (`wp-config.php`, `wp-settings.php`, `index.php`, `.htaccess`).
- **Dashboard com Telemetria e Pontuação de Saúde**.

---

### 3. Como Usar em Produção (Guia Rápido)

#### Passo 1: Executar o Esterilizador no Servidor
1. Envie `cerberus-sterilizer.php` para a raiz da sua hospedagem cPanel (`/home/seu_usuario/` ou `public_html`).
2. Acesse via navegador: `https://seusite.com/cerberus-sterilizer.php?token=c3ber0s-cl34n-v1`.
3. Clique em **"Esterilizar Hospedagem & Imunizar Sites"**.
4. Exclua o script ao finalizar a limpeza.

#### Passo 2: Instalar o Plugin CerberusWP Sentinel
1. No painel de cada WordPress, vá em **Plugins** -> **Adicionar Novo** -> **Enviar Plugin**.
2. Envie o arquivo `cerberus-sentinel.zip` e ative.
3. Acesse **CerberusWP 🛡️** no menu lateral e verifique a pontuação de saúde.

---

## 🇺🇸 English

### 1. The Threat: SCV Cross-Site Worm Architecture
Shared hosting environments host multiple domains under the same Unix user account. The malware disguised as `smooth-librarian-lite.php` (**SCV:4.3.24**) crawls parent directories (`dirname(ABSPATH)`) to discover all sibling websites and build a perpetual infection loop via `.user.ini`, `wp-config.php`, and stealth database backdoors.

### 2. The CerberusWP Arsenal
- **`cerberus-sterilizer.php`**: Atomic server-wide sterilizer with automated quarantine, auto-deploying the Must-Use vaccine across all sibling sites.
- **`000-antidoto-vaccine.php`**: Kernel-level memory intercepter disabling SCV boot routines.
- **`cerberus-sentinel` WordPress Plugin**: SQL-bypass administrator auditor and Core auto-repair guardian with an AI cyber minimalist dark interface.

---

## 📄 License
Released under the [MIT License](LICENSE). Built for sysadmins, security researchers, and webmasters worldwide.

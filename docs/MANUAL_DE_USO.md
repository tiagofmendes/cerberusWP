# Manual de Uso e Guia de Operação | CerberusWP Sentinel
### *A Suíte Definitiva de Defesa Ativa contra o Worm SCV, Erradicação de Infecção Cruzada em Hospedagens cPanel e Vacina Must-Use em Memória.*

---

## 🛡️ 1. Visão Geral e Arquitetura do CerberusWP

O **CerberusWP Sentinel** é uma solução de cibersegurança projetada para erradicar ataques persistentes do worm **SCV (Smart Custom Engine / `smooth-librarian-lite.php`)** em ambientes de hospedagem compartilhada (HostGator, Hostinger, Locaweb, cPanel) e servidores dedicados/VPS.

Em servidores compartilhados, dezenas de sites coexistem sob a mesma conta de usuário Linux (`/home/usuario/dominio1.com`, `/home/usuario/dominio2.com`). Quando um único site é invadido, o malware SCV navega pelas pastas superiores e contamina **todos os outros domínios irmãos**. Limpar apenas um site nunca resolve: os sites irmãos reinfectam o site limpo em questão de minutos.

O CerberusWP resolve esse dilema através da sua arquitetura de **3 Cabeças de Defesa Integradas**:

```
                              CERBERUS-WP
               ┌───────────────────┼───────────────────┐
               │                   │                   │
               ▼                   ▼                   ▼
           CABEÇA 1            CABEÇA 2            CABEÇA 3
     Esterilizador de Host    Vacina Must-Use    Plugin Sentinela
    (cerberus-sterilizer.php) (000-antidoto.php) (cerberus-sentinel)
               │                   │                   │
       Varredura atômica   Carrega no Estágio   Auditoria direta SQL,
      em todos os domínios   Zero da memória;    auto-cura de core e
     irmãos simultaneamente trava execução C2    toasts não-bloqueantes
```

---

## 🦠 2. Entendendo a Ameaça: O Ciclo do Worm SCV

O malware disfarçado como plugin ou arquivo de sistema explora quatro armadilhas coordenadas:

1. **Injeção de Pré-Execução (`.user.ini` / `.htaccess`)**:
   Injeta a diretiva `auto_prepend_file = '.../payload.php'`. Isso obriga o motor PHP do servidor a executar o vírus antes de qualquer script legítimo do WordPress.
2. **Inflação Artificiosa de Tamanho (`_sc_padf`)**:
   O vírus preenche os arquivos maliciosos com caracteres hexadecimais aleatórios até ultrapassar **5 MB**. Antivírus padrão de hospedagens (como cPanel Virus Scanner e Imunify360 Free) costumam ignorar arquivos maiores que 2 MB por economia de memória.
3. **Administradores Fantasmas no Banco de Dados**:
   Cria usuários administradores diretamente nas tabelas `wp_users` e `wp_usermeta` e aplica um filtro malicioso no gancho nativo `pre_user_query` do WordPress. Resultado: o administrador invasor existe, mas fica **completamente invisível** na lista de Usuários do painel admin.
4. **Infecção Cruzada Perpétua**:
   Executa comandos em loop varrendo `dirname(ABSPATH)`. Se você limpar 10 sites e esquecer 1, o site esquecido reinfecta os 10 em poucos segundos.

---

## 🚀 3. Guia Rápido de Emergência (3 Minutos)

Para desinfetar e proteger sua hospedagem agora mesmo:

### Passo 1: Enviar o Esterilizador para a Hospedagem
1. Localize o arquivo `hosting-sterilizer/cerberus-sterilizer.php` dentro da pasta do projeto.
2. Faça o upload desse arquivo para a raiz da sua conta cPanel (`/home/seu_usuario/`) ou dentro de `public_html/`.

### Passo 2: Acessar via Navegador e Esterilizar
1. Abra o navegador e acesse:
   ```
   https://seusite.com/cerberus-sterilizer.php?token=c3ber0s-cl34n-v1
   ```
2. O Cerberus detectará automaticamente todos os sites da sua hospedagem.
3. Clique em **"Esterilizar Hospedagem & Imunizar Sites"**.
4. Acompanhe a esterilização em tempo real via terminal web com streaming SSE.
5. Ao finalizar, baixe o arquivo de quarentena compactado gerado automaticamente.

### Passo 3: Instalar o Plugin Sentinela no WordPress
1. No painel de cada WordPress, vá em **Plugins** -> **Adicionar Novo** -> **Enviar Plugin**.
2. Envie o arquivo `cerberus-sentinel.zip` e clique em **Ativar**.
3. Acesse **CerberusWP 🛡️** no menu lateral para visualizar o painel de telemetria, saúde do site e auditoria de usuários.

---

## 🔧 4. Operação Detalhada do Esterilizador (`cerberus-sterilizer.php`)

### 4.1. Autenticação e Segurança
O script possui proteção nativa contra acesso não autorizado por meio da constante `STERILIZER_SECRET_TOKEN`. O token padrão é:
```php
define('STERILIZER_SECRET_TOKEN', 'c3ber0s-cl34n-v1');
```
> [!TIP]
> Você pode alterar essa constante no início do arquivo para uma senha pessoal caso deseje maior sigilo durante a manutenção.

### 4.2. Funcionalidades da Interface Web
- **Seletor de Escopo**: Permite varrer a conta inteira do cPanel ou apontar para um domínio específico.
- **Matriz de Ameaças**: Exibe cada arquivo comprometido, categoria do malware, gravidade e botão **"Inspecionar Código"** para ver o trecho exato do payload antes de qualquer ação.
- **Cofre de Quarentena Automática (.zip)**: Antes de excluir ou sanitizar qualquer arquivo, o Cerberus empacota tudo em um `.zip` com timestamp e arquivo `manifest.json`.
- **Botão de Rollback (1 Clique)**: Se por qualquer motivo você precisar reverter as alterações, clique em **"Reverter / Restaurar"** na listagem do cofre.
- **Implantação Automática de Vacina**: Durante a limpeza, o esterilizador já injeta a vacina Must-Use em cada WordPress detectado.

### 4.3. Execução via Linha de Comando (CLI / SSH)
Se você possui acesso SSH à hospedagem, pode rodar o esterilizador diretamente pelo terminal:

```bash
# Modo Simulação (Dry-run): apenas audita sem alterar nada
php cerberus-sterilizer.php --dry-run

# Modo Esterilização Real com Quarentena Automática
php cerberus-sterilizer.php --clean

# Apontando para um diretório específico
php cerberus-sterilizer.php --target=/home/usuario/meusite.com --clean
```

---

## 🛡️ 5. Operação do Plugin WordPress (`cerberus-sentinel`)

### 5.1. Dashboard Cyber Minimalist
Ao acessar **CerberusWP** no menu administrativo:
- **Pontuação de Saúde (0% a 100%)**: Avalia a integridade do Core, presença de scripts em `mu-plugins`, persistências na tabela `wp_options` e administradores suspeitos.
- **HUD com Telemetria Ativa**: Monitora em tempo real o status de defesa.

### 5.2. Módulos de Auditoria e Reparo

#### 1. Integridade do Core do WordPress
- **O que faz**: Monitora arquivos vitais (`wp-config.php`, `wp-settings.php`, `index.php`, `.htaccess` e `.user.ini`).
- **Ação**: O botão **"Restaurar Arquivos de Core"** remove diretivas de injeção (`auto_prepend_file`, doorways japoneses de SEO spam) e restabelece os arquivos originais sem afetar a conexão com o banco de dados.

#### 2. Guardião de MU-Plugins (`wp-content/mu-plugins/`)
- **O que faz**: Inspeciona a pasta de carregamento prioritário do WordPress.
- **Ação**: O botão **"Expurgar Ameaças de MU-Plugins"** elimina scripts variantes (`smooth-librarian-lite.php`, `.bt_*`, `.rd_*`) e garante a presença da vacina `000-antidoto-vaccine.php`.

#### 3. Persistências no Banco (`wp_options`)
- **O que faz**: Realiza varredura SQL direta em busca de chaves registradas pelo worm (como `sc_options`, `smooth_librarian_boot`, tokens de botnet).
- **Ação**: O botão **"Expurgar Todas as Opções Maliciosas"** limpa a tabela instantaneamente via AJAX com feedback por Cyber Toast.

#### 4. Auditoria Direta de Usuários (SQL Bypass)
- **O que faz**: Realiza uma consulta SQL pura diretamente na tabela `wp_users`, contornando ganchos maliciosos em `pre_user_query`.
- **Heurísticas**: Identifica contas com nomes gerados por dicionários aleatórios sem vogais e domínios de e-mail temporários (`.xyz`, `example.com`).
- **Ação**: Botão individual para excluir o usuário invasor de forma definitiva do banco.

---

## 🧪 6. Suíte de Testes e Validação Automatizada (Sandbox)

O projeto inclui uma suíte automatizada de simulação em sandbox (`hosting-sterilizer/test_sandbox.py`) que valida a eficácia do esterilizador contra todos os vetores conhecidos do worm SCV:

### Executando os Testes Automatizados
No terminal, execute:

```bash
python hosting-sterilizer/test_sandbox.py
```

### O que a suíte valida (8 Checagens Críticas):
1. **Remoção de MU-Plugins virais**: Garante eliminação de `smooth-librarian-lite.php`.
2. **Remoção de diretórios ocultos de Core**: Valida exclusão de `.sc_*`.
3. **Higienização de `.user.ini`**: Confirma remoção da diretiva `auto_prepend_file`.
4. **Desinfecção de `wp-config.php`**: Valida a remoção do marcador `/* SC_WC */`.
5. **Restauração de `wp-settings.php`**: Verifica eliminação do require malicioso `compat-utf8.php`.
6. **Expurgo de Webshells numéricas**: Valida exclusão de pastas suspeitas (ex: `586381/`).
7. **Restauração do `index.php`**: Garante reversão para o cabeçalho original limpo do WordPress.
8. **Expurgo de temas e portas dos fundos**: Confirma neutralização de diretórios forjados.

---

## 🔒 7. Hardening Pós-Limpeza (Boas Práticas Recomendadas)

Após a esterilização completa da conta:

1. **Alterar as Senhas de Todos os Usuários e FTP**:
   Altere a senha do cPanel, do banco de dados MySQL e de todos os administradores legítimos do WordPress.
2. **Renovar as Chaves de Segurança do WordPress (`SALT_KEYS`)**:
   Acesse o gerador oficial `https://api.wordpress.org/secret-key/1.1/salt/` e substitua as constantes no seu `wp-config.php`. Isso invalida sessões antigas ou cookies clonados.
3. **Bloquear Execução de PHP na Pasta de Uploads**:
   Crie um arquivo `.htaccess` dentro de `wp-content/uploads/` com o conteúdo:
   ```apache
   <Files *.php>
   deny from all
   </Files>
   ```
4. **Remover o Script Esterilizador**:
   Após confirmar que todos os sites estão limpos e funcionando normalmente, delete o arquivo `cerberus-sterilizer.php` da raiz do servidor.

---

## ❓ 8. Perguntas Frequentes (FAQ) & Troubleshooting

**P: O esterilizador pode quebrar meus sites?**
R: Não. O CerberusWP foi construído com salvaguardas rigorosas. Antes de qualquer exclusão ou modificação em arquivos, um arquivo `.zip` com todo o conteúdo original é criado no cofre de quarentena. Você pode restaurar qualquer site a qualquer momento com um clique.

**P: Recebi um erro `504 Gateway Timeout` ao escanear a hospedagem. O que fazer?**
R: Hospedagens compartilhadas muito restritas podem limitar o tempo de resposta HTTP. Nesse caso:
1. No campo de caminho personalizado, escaneie uma pasta de cada vez (ex: `public_html/site1`).
2. Ou execute via SSH: `php cerberus-sterilizer.php --clean`.

**P: A vacina Must-Use deixa o WordPress lento?**
R: Não. A vacina é ultra-leve (menos de 2 KB) e adiciona menos de 0.001 segundos ao ciclo de vida do WordPress, atuando apenas como um interceptor de constantes maliciosas na memória RAM.

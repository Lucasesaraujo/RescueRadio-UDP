# RescueRadio-UDP

Implementacao UDP nativa para um canal de radio operacional de equipe de resgate.

Diferente da versao TCP, esta base foi desenhada para o melhor caso de uso de
datagramas:

- Baixa latencia para trafego de voz/texto curto
- Estado de sessao leve no servidor
- Heartbeat para detectar inatividade rapidamente
- Mensagens com prioridade taticas (`routine`, `urgent`, `critical`)
- Confirmacao e reenvio de mensagens `critical` no nivel da aplicacao

## Arquitetura

- `server.py`: loop de eventos UDP com `recvfrom()` e manutencao de sessoes
- `client.py`: terminal interativo com heartbeat e comandos operacionais
- `protocol.py`: protocolo compartilhado (JSON, versao, validacao)
- `auth.py`: autenticacao de operadores (PBKDF2-HMAC-SHA256)
- `admin.py`: cadastro/listagem/remocao/reset de operadores

## Protocolo UDP (resumo)

Cada datagrama e um objeto JSON:

```json
{"v":1,"type":"radio","session_id":"...","text":"...","priority":"urgent"}
```

Eventos principais:

- `auth`: login do operador
- `auth_ok`, `auth_fail`, `auth_ban`
- `heartbeat`, `heartbeat_ack`
- `radio`: mensagem operacional
- `ack`: confirmacao de entrega de `radio` critica
- `command`: comandos de controle
- `briefing`, `system`, `error`, `critical_update`, `logout_ack`

## Requisitos

- Python 3.10+
- `python-dotenv` para `admin.py`

```powershell
pip install -r requirements.txt
```

## Preparacao

1. Copie `.env.example` para `.env` e defina `ADMIN_USER` e `ADMIN_PASSWORD`.
2. Cadastre operadores:

```powershell
py admin.py
```

## Execucao

Servidor:

```powershell
py server.py
```

Cliente:

```powershell
py client.py
```

Cliente em host/porta customizados:

```powershell
py client.py 192.168.0.10 12345
```

## Comandos do cliente

- `/membros`: lista membros do canal atual
- `/status`: status operacional do canal
- `/ajuda`: ajuda remota retornada pelo servidor
- `/canal <nome>`: troca de canal tatico
- `/urg <texto>`: envia mensagem urgente
- `/crit <texto>`: envia mensagem critica (com ack/reenvio)
- `/sair`: encerra a sessao
- `/help`: ajuda local

Mensagem sem prefixo e enviada como `routine`.

## Observacoes operacionais

- UDP nao garante entrega, ordem ou ausencia de duplicacao.
- O projeto compensa parcialmente isso em mensagens criticas via ack/reenvio.
- Nao ha criptografia de transporte. Para uso real, opere sobre VPN/TLS/tunel.

# Secrets Broker

[English](README.md) | 简体中文

一个自托管的 **AI Agent 密钥代理**。密钥保存在任意 Bitwarden 兼容的 vault
（NodeWarden / Vaultwarden / Bitwarden）里，broker 只给 Agent 暴露很窄的
API / MCP 接口，并加上每个 Agent 独立的 token、显式审批、限时授权、读取次数和审计日志。

核心理念：**模型不需要看到密钥本身**。Agent 发起请求 → 你在网页 / Telegram /
ntfy / Gotify / 微信（wxpush）里点同意 → Agent 拿到值；每次读取都能追溯到具体 Agent。


## Cloudflare Workers 版本

另有 Cloudflare Workers 原生版本：
<https://github.com/otscup/secrets-broker-workers>。它直接读取 NodeWarden 的 D1，
浏览器端做 KDF，Durable Object 保存会话，支持 MCP OAuth 2.1、Agent token、
文件夹隔离和跨账户复制，不需要 NAS、Docker 或隧道。

可移植的 Agent Skill 和 stdio MCP 桥接器：
<https://github.com/otscup/secrets-broker-skill>。

## 装之前先试试

<https://demo.otscup.com> 用同一套界面跑在虚拟密钥库上：不用安装、不用
NodeWarden、没有任何真实凭据。自带 OIDC 身份提供者，批准请求、读取密钥、看审计
记录，一分钟能点完一遍。demo 会自己重置，随便点。 (Link the online demo)

## 功能

- **复用现有 vault**：通过 Bitwarden CLI 访问 NodeWarden/Vaultwarden/Bitwarden，
  不需要再维护一套加密数据库。
- **默认人工审批**：首次读取产生待批准请求；可授权一次 / 1 小时 / 24 小时 / 7 天 / 永久，
  可延长、撤销、恢复、限制读取次数。常用条目可以设为**免审批（只记录）**，实现无感读取。
- **Agent 独立身份**：每个 Agent 一个 token（落盘为 SHA-256 哈希），可设置可读条目、
  是否允许写入、可单独轮换/删除。
- **审计**：谁在什么时候读了哪个密钥、通过什么渠道批准、读了多少次。
- **通知与审批**：网页、Telegram 内联按钮、ntfy 签名链接、Gotify、wxpush（微信）。
- **MCP**：
  - HTTP：`POST /mcp`，支持 OAuth 2.1（自动发现 + 动态注册 + PKCE + 浏览器授权）；
  - stdio：`mcp-server.mjs`，额外支持 `exec_with_secrets`（密钥注入子进程，模型不可见）。
- **网页管理**：概览图表、密钥（网址/分组/搜索/编辑）、Agents、授权、日志、
  个人资料（2FA、OIDC 绑定）、设置。
- **安全**：AES-256-GCM 加密敏感字段；Agent token 哈希；登录限速；可选 TOTP；
  自动解锁密码加密落盘。

## 快速开始（Docker）

```bash
git clone https://github.com/otscup/secrets-broker.git
cd secrets-broker
./deploy/install.sh
```

脚本会询问 vault 地址、API key、管理密码和公开地址，然后自动写 `deploy/.env`
并执行 `docker compose up -d --build`。

打开 <http://127.0.0.1:8788/>，用管理密码登录并入 vault 主密码解锁。

Docker 镜像内已安装 `@bitwarden/cli`，宿主机不需要装 `bw`；只有本地直接
`npm start` 时才需要自己安装或通过 `SECRETS_BROKER_BW` 指定。

手动方式：

```bash
cp deploy/.env.example deploy/.env
# 编辑 deploy/.env
docker compose up -d --build
```

## Agent API

```bash
# 按条目名读取（首次会进入待审批）
curl -H "Authorization: Bearer $AGENT_TOKEN" \
  "https://broker.example.com/secret?name=tavily-api-key"

# 按网址/域名匹配
curl -H "Authorization: Bearer $AGENT_TOKEN" \
  "https://broker.example.com/secret?url=https://example.com"

# Agent 写入（需要先在页面开启该 Agent 的写入权限）
curl -X POST -H "Authorization: Bearer $AGENT_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"project/prod/api-key","value":"...","url":"https://example.com"}' \
  "https://broker.example.com/agent/items/save"
```

## MCP

### HTTP

```
https://broker.example.com/mcp
```

- **OAuth 2.1**：支持 MCP 授权发现的客户端只需填 URL，第一次连接会打开浏览器让你点允许，
  之后拿到 24 小时 access token，不用手工复制 API token；
- **Bearer token**：也可以直接用 Agent token。

工具：`list_secrets`、`create_secret`、`request_access`；`get_secret` 默认关闭，
设置 `MCP_ALLOW_READ=1` 才暴露（值会进入模型上下文）。

### stdio

```json
{
  "mcpServers": {
    "secrets": {
      "command": "node",
      "args": ["/path/to/secrets-broker/mcp-server.mjs"],
      "env": {
        "BROKER_URL": "https://broker.example.com",
        "BROKER_AGENT_TOKEN": "<agent token>"
      }
    }
  }
}
```

## 通知渠道

在「设置」或环境变量中配置，均为可选：

- **ntfy**：通知里带签名的「允许一次 / 24 小时 / 拒绝」链接；
- **Telegram**：内联按钮直接审批（broker 用长轮询处理，不需要公网 webhook）；
- **Gotify**：Gotify URL + App Token；
- **wxpush**：`WXPUSH_URL` + API Token，推送到微信。

## 安全模型

- 主密码只存在内存；可选自动解锁文件使用 AES-256-GCM 加密，密钥在 `encryption.key`；
- Agent token 在 `config.json` 中只存 SHA-256，明文保存在加密的 `agent-tokens.json`
  （仅用于页面复制/轮换），也可以改用环境变量；
- 管理页：密码（可选 TOTP）或 OIDC（PKCE），登录限速，HttpOnly cookie；
- 每次读取都需要有效授权或显式审批，并写入审计；
- 审批链接带 HMAC 签名和 10 分钟过期；
- 自托管服务请放在内网或带访问策略的隧道后面，不要直接暴露 8788。

## 配置

常用环境变量：

| 变量 | 说明 |
|---|---|
| `SECRETS_BROKER_HOME` | 数据目录（默认 `~/.secrets-broker`） |
| `SECRETS_BROKER_PORT` / `SECRETS_BROKER_BIND` | 监听端口/地址 |
| `SECRETS_BROKER_ADMIN_PASSWORD` | 管理页密码 |
| `BROKER_PUBLIC_URL` | 审批链接/OAuth 使用的公开地址 |
| `SECRETS_BROKER_BW` | `bw` 可执行文件或 `bw.js` 路径 |
| `SECRETS_BROKER_ENCRYPTION_KEY` | 可选 32 字节 base64 加密密钥 |
| `MCP_ALLOW_READ` | 是否暴露 MCP `get_secret` |

vault 地址、OIDC、通知等也可以在网页设置里修改，保存到 `config.json`。

## 目录

```
server.mjs            broker + 管理页 + HTTP API + MCP HTTP + OAuth 服务
mcp-server.mjs        stdio MCP 适配器
wh.mjs                CLI helper（get / run --var）
docker-compose.yml    一键 Docker 部署
deploy/Dockerfile     镜像（内含 @bitwarden/cli）
deploy/install.sh     交互式安装脚本
docs/                 英文文档
```

## 许可

MIT

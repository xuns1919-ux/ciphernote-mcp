<div align="center">

# 🔐 CipherNote MCP

**一个本地优先、加密存储的 MCP 私人笔记本**

让支持 MCP 的 AI 客户端安全地保存、检索和管理长期笔记。

![License](https://img.shields.io/badge/license-MIT-2ea44f)
![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A520-339933?logo=nodedotjs&logoColor=white)
![Python](https://img.shields.io/badge/Python-%E2%89%A53.10-3776AB?logo=python&logoColor=white)
![Storage](https://img.shields.io/badge/storage-local--only-6f42c1)

</div>

---

## ✨ 功能特点

| 功能 | 说明 |
| --- | --- |
| 🔒 加密存储 | 标题、正文和标签在写入 SQLite 前使用 AES-256-GCM 加密 |
| 🏠 本地优先 | 不包含云同步、遥测、分析或任何远程 API 请求 |
| 🔎 本地搜索 | 笔记仅在本机内存中解密和搜索 |
| 🧩 MCP 支持 | 支持本地 stdio 和远程 Streamable HTTP |
| 🌐 安全远程访问 | 内置 Bearer 鉴权、Host 校验和可选 TLS |
| 🛡️ 凭据拦截 | 自动拒绝疑似密码、令牌、私钥等敏感凭据 |
| 📦 轻量部署 | Node.js 负责 MCP 通信，Python 负责加密存储 |

## 🧰 MCP 工具

CipherNote 提供以下五个工具：

| 工具 | 用途 |
| --- | --- |
| `private_note_write` | 创建加密笔记 |
| `private_note_search` | 根据关键词搜索笔记 |
| `private_note_read` | 根据笔记 ID 读取完整内容 |
| `private_note_recent` | 查看最近笔记的元数据，不返回正文 |
| `private_note_delete` | 永久删除指定笔记 |

## 🚀 快速开始

### 1. 环境要求

- Node.js 20 或更高版本
- Python 3.10 或更高版本
- 系统命令行中可以使用 `python`；Linux/macOS 默认也支持 `python3`

### 2. 下载并安装

```bash
git clone https://github.com/xuns1919-ux/ciphernote-mcp.git
cd ciphernote-mcp
npm install
python -m venv .venv
```

激活虚拟环境：

```bash
# Windows PowerShell
.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate
```

安装 Python 依赖：

```bash
python -m pip install -r requirements.txt
```

### 3. 生成加密密钥

```bash
python scripts/generate_key.py
```

命令会输出类似下面的内容：

```text
CIPHERNOTE_KEY=base64:YOUR_RANDOM_KEY
```

> [!IMPORTANT]
> 请把密钥保存在密码管理器或客户端的安全存储中。不要将真实密钥写入 Git，也不要与数据库放在同一个备份位置。

### 4. 配置 MCP 客户端

将下面配置中的项目路径和密钥替换为你自己的值：

```json
{
  "mcpServers": {
    "ciphernote": {
      "command": "node",
      "args": ["/absolute/path/to/ciphernote-mcp/src/server.js"],
      "env": {
        "CIPHERNOTE_KEY": "base64:YOUR_RANDOM_KEY"
      }
    }
  }
}
```

建议通过客户端提供的密钥管理功能传入 `CIPHERNOTE_KEY`，不要直接把真实密钥写进会被同步或提交的配置文件。

### 5. 运行服务

```bash
npm start
```

默认模式继续使用标准输入输出（stdio）与 MCP 客户端通信。协议消息写入标准输出，诊断信息写入标准错误。

## 🌐 Streamable HTTP

v0.3.0 起可以直接提供原生 Streamable HTTP，无需额外 wrapper。HTTP 模式始终要求至少
32 字符的 Bearer Token；缺少或错误的 Token 返回 `401 Unauthorized`。

生成 Token 并限制文件权限：

```bash
umask 077
openssl rand -hex 32 > /etc/ciphernote-mcp/token
```

推荐在 Nginx、Caddy 等 TLS 反向代理后仅监听回环地址：

```bash
export CIPHERNOTE_TRANSPORT=http
export CIPHERNOTE_HOST=127.0.0.1
export CIPHERNOTE_PORT=18060
export CIPHERNOTE_HTTP_PATH=/mcp
export CIPHERNOTE_AUTH_TOKEN_FILE=/etc/ciphernote-mcp/token
export CIPHERNOTE_ALLOWED_HOSTS=notes.example.com
npm start
```

客户端连接 `https://notes.example.com/mcp`，传输方式选择 Streamable HTTP，并发送：

```text
Authorization: Bearer YOUR_TOKEN
```

反向代理必须保留 `Authorization` 请求头，并关闭响应缓冲。Nginx 示例：

```nginx
location = /mcp {
    proxy_pass http://127.0.0.1:18060/mcp;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 3600s;
}
```

也可以由 CipherNote 直接终止 TLS，此时证书和私钥必须同时设置：

```bash
export CIPHERNOTE_TRANSPORT=http
export CIPHERNOTE_HOST=0.0.0.0
export CIPHERNOTE_PORT=8443
export CIPHERNOTE_AUTH_TOKEN_FILE=/etc/ciphernote-mcp/token
export CIPHERNOTE_ALLOWED_HOSTS=notes.example.com
export CIPHERNOTE_TLS_CERT=/etc/letsencrypt/live/notes.example.com/fullchain.pem
export CIPHERNOTE_TLS_KEY=/etc/letsencrypt/live/notes.example.com/privkey.pem
npm start
```

非回环监听如果没有 TLS 或没有显式的允许 Host 列表，服务会拒绝启动。生产环境只应开放
HTTPS 端口，不要将未加密的后端端口暴露到公网。`GET /healthz` 是不含敏感信息的健康检查。

## ⚙️ 环境变量

| 变量 | 必需 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CIPHERNOTE_KEY` | 是 | 无 | 32 字节密钥，必须使用 `base64:` 或 `hex:` 前缀 |
| `CIPHERNOTE_DB` | 否 | 系统本地数据目录 | 自定义 SQLite 数据库路径 |
| `CIPHERNOTE_PYTHON` | 否 | Windows 使用 `python`，其他系统使用 `python3` | 自定义 Python 可执行文件 |
| `CIPHERNOTE_TRANSPORT` | 否 | `stdio` | `stdio` 或 `http` |
| `CIPHERNOTE_HOST` | HTTP | `127.0.0.1` | HTTP 监听地址 |
| `CIPHERNOTE_PORT` | HTTP | `18060` | HTTP 监听端口 |
| `CIPHERNOTE_HTTP_PATH` | HTTP | `/mcp` | Streamable HTTP 路径 |
| `CIPHERNOTE_AUTH_TOKEN` | 二选一 | 无 | 至少 32 字符的 Bearer Token |
| `CIPHERNOTE_AUTH_TOKEN_FILE` | 二选一 | 无 | 从受保护文件读取 Bearer Token |
| `CIPHERNOTE_ALLOWED_HOSTS` | 远程 HTTP | 回环地址 | 逗号分隔的允许 Host 名称 |
| `CIPHERNOTE_TLS_CERT` | 可选 | 无 | PEM 证书链，必须和 TLS 私钥同时设置 |
| `CIPHERNOTE_TLS_KEY` | 可选 | 无 | PEM 私钥，必须和 TLS 证书同时设置 |
| `CIPHERNOTE_MAX_BODY_BYTES` | 否 | `1048576` | HTTP 请求体限制，最大 10 MiB |

默认数据库位置：

- Windows：`%LOCALAPPDATA%\ciphernote-mcp\ciphernote.db`
- Linux：`$XDG_DATA_HOME/ciphernote-mcp/ciphernote.db`，未设置时使用 `~/.local/share`
- macOS：默认与其他 Unix 系统一致，也可以通过 `CIPHERNOTE_DB` 指定位置

## 🔐 隐私与安全模型

### 已加密的数据

- 笔记标题
- 笔记正文
- 标签

### 未隐藏的元数据

- 数据库文件大小
- 笔记数量和密文长度
- 笔记 ID
- 创建和更新时间
- 重要性等级
- 访问模式

CipherNote 主要保护被单独复制或泄露的数据库文件。它不能抵御以下情况：

- 攻击者已经控制运行 CipherNote 的设备
- 其他进程可以读取 `CIPHERNOTE_KEY` 或检查进程内存
- MCP 客户端本身不可信
- 管理员权限、恶意软件或键盘记录器

> [!WARNING]
> CipherNote 不是密码管理器。请勿用它保存密码、API Key、Cookie、访问令牌、SSH 私钥或恢复码。

更多信息请阅读 [安全策略](SECURITY.md)。

## 💾 备份与恢复

请分别备份数据库和加密密钥。丢失密钥后，笔记内容无法恢复。

SQLite 运行时可能生成 `-wal` 和 `-shm` 文件。为了获得一致的备份，建议先停止 MCP 服务，再复制数据库；或者同时备份数据库及其 WAL 文件。

## 🗂️ 项目结构

```text
ciphernote-mcp/
├── scripts/
│   └── generate_key.py   # 安全生成随机密钥
├── src/
│   ├── server.js         # stdio/HTTP 启动入口
│   ├── ciphernote.js     # MCP server factory 和工具注册
│   ├── http.js           # Streamable HTTP、TLS 和 Bearer 鉴权
│   └── store.py          # 加密和 SQLite 存储层
├── tests/
│   ├── http.test.js      # HTTP、鉴权、Host 和 MCP 集成测试
│   └── test_store.py     # 存储、加密和凭据拦截测试
├── .env.example          # 环境变量示例，不包含真实密钥
├── SECURITY.md           # 安全策略与威胁模型
└── requirements.txt      # Python 依赖
```

## 🧪 开发与测试

```bash
python -m pip install -r requirements.txt
npm test
node --check src/server.js
```

测试会使用临时数据库，不会读取你的真实笔记。

## 🤝 参与贡献

欢迎提交 Issue 和 Pull Request。提交代码前请确保：

1. 没有包含真实笔记、数据库、密钥或个人信息。
2. 所有测试均已通过。
3. 新增安全相关功能时同步更新 `SECURITY.md`。

发现安全漏洞时，请不要在公开 Issue 中发布利用代码、真实密钥或笔记数据库。请使用 GitHub 的私密漏洞报告功能。

## 📄 开源许可

本项目使用 [MIT License](LICENSE)。

---

<div align="center">

**数据属于你，密钥也属于你。**

</div>


## Universal Privacy Mode（v0.3.0）

CIPHERNOTE_PRIVACY_MODE 默认是 standard，未设置时保持 v0.2.0 的兼容行为：

- standard：五个旧工具全部可见；明文写入、搜索摘要和完整读取仍可能进入 MCP 客户端参数/结果。
- private：默认不注册明文写入工具；搜索只返回匹配数量和 note ID，recent 隐藏标题/标签，read/delete 需要独立安全页面；增加 private_note_commit_draft。
- strict：不返回正文、标题或标签；搜索只返回数量，recent 只返回 ID；普通 MCP 不提供明文写入，完整内容仅能在认证的 Secure Capture 页面处理。

标准 MCP 无法控制客户端是否显示、复制或保存已经收到的工具参数。因此 private/strict 不把“折叠工具卡片”当作隐私边界。

### Secure Capture

HTTP 模式启用 private/strict 时，默认提供：

    https://<你的域名>/notes/capture

页面登录使用同一个部署 Bearer Token 建立短时 HttpOnly、SameSite 会话。标题、正文和标签从浏览器通过 HTTPS 直接提交服务端，不经过 MCP 工具参数。

页面支持：

- 直接安全保存；
- 创建短时一次性 draft_id；
- MCP 仅调用 private_note_commit_draft({"draft_id":"draft_..."}) 完成提交。

draft 内容在 SQLite 的 secure_drafts 表中加密保存，默认 900 秒过期，成功提交后删除，绑定登录主体并防止重复提交。draft ID 不包含标题或正文。

当前主体绑定是“部署 Bearer Token 的哈希 + 浏览器会话”，不是多用户账户系统。多个用户共享一个 Bearer Token 时仍共享同一权限；需要真正用户隔离时，请为每个主体部署独立实例或在反向代理增加身份映射。不要把 user_id 作为工具参数当作授权依据。

### 配置

    CIPHERNOTE_PRIVACY_MODE=private
    CIPHERNOTE_SECURE_CAPTURE_ENABLED=true
    CIPHERNOTE_SECURE_CAPTURE_TTL_SECONDS=900
    CIPHERNOTE_DIRECT_WRITE_ENABLED=false

private/strict 模式下如果启用 CIPHERNOTE_DIRECT_WRITE_ENABLED=true，普通写入参数可能出现在客户端历史和模型上下文中，不能称为“无明文传输”。

### 能力边界

- 数据库加密、MCP 参数、MCP 返回值、客户端历史和模型上下文是五个不同层面。
- private/strict 的搜索结果不能让模型假装已经读过正文；只有 note ID/计数可见。
- 无法实际运行的客户端界面不应标记为隐私 PASS；需分别测试 Operit、Anejul、Kelivo、Opeiro、Claude Desktop、Cherry Studio。

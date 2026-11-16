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
| 🧩 MCP 支持 | 可连接支持 MCP 的 AI 客户端 |
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

服务使用标准输入输出（stdio）与 MCP 客户端通信。协议消息写入标准输出，诊断信息写入标准错误。

## ⚙️ 环境变量

| 变量 | 必需 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CIPHERNOTE_KEY` | 是 | 无 | 32 字节密钥，必须使用 `base64:` 或 `hex:` 前缀 |
| `CIPHERNOTE_DB` | 否 | 系统本地数据目录 | 自定义 SQLite 数据库路径 |
| `CIPHERNOTE_PYTHON` | 否 | Windows 使用 `python`，其他系统使用 `python3` | 自定义 Python 可执行文件 |

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
│   ├── server.js         # MCP 服务入口
│   └── store.py          # 加密和 SQLite 存储层
├── tests/
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

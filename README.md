# SSH Hub

SSH Hub 是一个 Go 服务，可通过 HTTP 上的 MCP 协议，让 agent 使用预先配置的 SSH 主机。项目包含主机和密钥管理 Web UI、本地管理员登录、可选的第三方 OpenID Connect 登录、OAuth 授权、动态客户端注册和 Docker 镜像。

## 使用 Docker Compose 启动

```sh
cp .env.example .env
docker compose up --build -d
docker compose logs ssh-hub
```

打开 `http://localhost:8080`。如果首次启动没有设置 `SSHHUB_ADMIN_PASSWORD`，从容器日志复制一次性初始化口令，并设置管理员密码。管理员用户名固定为 `admin`。

远程部署时，将 `SSHHUB_PUBLIC_URL` 设置为公网 HTTPS 源站地址（不要带末尾斜杠），并在 SSH Hub 前配置 HTTPS 反向代理。反向代理需要保留外部 `Host`。不要把未加密的 HTTP 监听端口暴露到不可信网络。

## 配置第三方身份提供方

服务可选接入支持 OpenID Connect Discovery 的身份提供方，例如 Keycloak、Auth0、Google 或 Microsoft Entra ID。设置 `.env` 中的 `SSHHUB_OIDC_ISSUER`、`SSHHUB_OIDC_CLIENT_ID` 和 `SSHHUB_OIDC_CLIENT_SECRET`，并在身份提供方登记回调地址（用实际域名替换示例域名）：

```text
https://your-host.example/auth/oidc/callback
```

必须至少配置一个管理员允许列表：`SSHHUB_OIDC_ALLOWED_EMAILS` 接收逗号分隔的邮箱（只接受 IdP 标记为已验证的邮箱），`SSHHUB_OIDC_ALLOWED_SUBJECTS` 接收逗号分隔的精确 OIDC `sub` 值。未列入允许列表的 IdP 用户不能进入管理界面。成功登录后仍会继续走 SSH Hub 的 OAuth 授权确认页。`SSHHUB_OIDC_LABEL` 可自定义登录按钮文字；本地管理员密码登录仍然可用。

## 连接 MCP 客户端

在 MCP 客户端中添加以下地址：

```text
https://your-host.example/mcp
```

服务提供 OAuth 授权服务器和受保护资源发现接口，支持公开客户端动态注册、授权码流程、S256 PKCE 和资源绑定。客户端注册后会打开浏览器，要求管理员登录并明确批准授权。客户端请求 refresh token 时，服务会签发并轮换有效期为 30 天的 refresh token；access token 有效期为 1 小时。

内置工具：

- `ssh_list_hosts`：列出管理员配置的 SSH 主机。
- `ssh_exec`：以配置的 SSH 用户身份在远程主机执行 Shell 命令。

## 配置 SSH 访问

在 Web UI 中添加私钥。支持未加密和带口令的 OpenSSH/PEM 私钥。私钥和口令会先用 AES-256-GCM 加密，再写入数据目录。加密密钥单独保存在 `master.key`，权限为仅所有者可读写；备份时请将整个数据目录一起保存。

添加主机时，需要填写地址、SSH 用户、密钥和服务器主机指纹。可在可信机器上运行以下命令获取 ed25519 主机指纹：

```sh
ssh-keyscan -t ed25519 your-host.example | ssh-keygen -lf -
```

每次连接都会校验 SHA256 指纹。每台主机的命令超时可设置为 1 到 300 秒；stdout 和 stderr 各限制为 512 KiB。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SSHHUB_LISTEN_ADDR` | `:8080` | HTTP 监听地址 |
| `SSHHUB_DATA_DIR` | Docker 中的 `/data` | 持久化数据目录 |
| `SSHHUB_PUBLIC_URL` | `http://localhost:8080` | OAuth 发现和资源绑定所用的公网源站地址 |
| `SSHHUB_ADMIN_PASSWORD` | 未设置 | 可选的首次管理员密码，至少 12 个字符 |
| `SSHHUB_OIDC_ISSUER` | 未设置 | OIDC issuer URL；应支持 `/.well-known/openid-configuration` |
| `SSHHUB_OIDC_CLIENT_ID` | 未设置 | 在身份提供方注册的客户端 ID |
| `SSHHUB_OIDC_CLIENT_SECRET` | 未设置 | 在身份提供方注册的客户端密钥 |
| `SSHHUB_OIDC_ALLOWED_EMAILS` | 未设置 | 允许登录的已验证邮箱，多个值用逗号分隔 |
| `SSHHUB_OIDC_ALLOWED_SUBJECTS` | 未设置 | 允许登录的精确 OIDC `sub` 值，多个值用逗号分隔 |
| `SSHHUB_OIDC_LABEL` | `使用第三方账号登录` | 登录页面上的 IdP 按钮文字 |

服务镜像构建后标记为 `ssh-hub:local`。Docker 构建使用仓库内的 Go 依赖，不需要在构建容器中访问 Go 模块代理。

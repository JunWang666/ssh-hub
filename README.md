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

If the management UI has a separate origin configured with `SSHHUB_ADMIN_URL`, register its callback too:

```text
https://your-admin-host.example/auth/oidc/callback
```

When `SSHHUB_ADMIN_URL` is set, the public origin serves MCP and OAuth routes while hiding the management UI and API. Put the separate admin origin behind Pangolin authentication.

必须至少配置一个管理员允许列表：`SSHHUB_OIDC_ALLOWED_EMAILS` 接收逗号分隔的邮箱（只接受 IdP 标记为已验证的邮箱），`SSHHUB_OIDC_ALLOWED_SUBJECTS` 接收逗号分隔的精确 OIDC `sub` 值。未列入允许列表的 IdP 用户不能进入管理界面。成功登录后仍会继续走 SSH Hub 的 OAuth 授权确认页。`SSHHUB_OIDC_LABEL` 可自定义登录按钮文字；本地管理员密码登录仍然可用。

## 连接 MCP 客户端

在 MCP 客户端中添加以下地址：

```text
https://your-host.example/mcp
```

服务提供 OAuth 授权服务器和受保护资源发现接口，支持公开客户端动态注册、授权码流程、S256 PKCE 和资源绑定。客户端注册后会打开浏览器，要求管理员登录并明确批准授权。客户端请求 refresh token 时，服务会签发并轮换有效期为 30 天的 refresh token；access token 有效期为 1 小时。

内置工具：

- `ssh_list_hosts`：列出管理员配置的 SSH 主机。
- `ssh_exec`：按客户端机器权限和审批策略执行 Shell 命令，保存会话审计。
- `ssh_session_status`：查询当前客户端自己的执行会话和结果。

## 配置 SSH 访问

管理台支持三种密钥来源：

- **生成密钥对**：默认生成 Ed25519，私钥和 `.pub` 文件保存在 `/data/keys`，私钥权限为 `0600`，随数据卷持久化。
- **挂载私钥**：把宿主机目录只读挂载到 `/keys`，在管理台填写相对文件名（例如 `id_ed25519`）。运行时直接读取文件，不把私钥复制进数据库。支持口令，口令加密保存。文件访问限制在挂载目录内；文件被替换后公钥不匹配会拒绝执行，需要重新登记。
- **导入私钥**：兼容已有导入记录，私钥和口令仍用 AES-256-GCM 加密保存在数据目录。

创建密钥后，点击“安装公钥”，复制管理台给出的命令，在目标服务器以希望 SSH 登录的用户执行：

```sh
curl -fsSL 'https://your-host.example/install/<random-token>' | sh
```

此链接只提供公钥安装脚本；另有 `/public-keys/<random-token>` 可下载纯公钥。脚本追加公钥到当前用户的 `~/.ssh/authorized_keys`，保留已有条目和相同公钥的限制，不重复添加，并设置目录 `0700`、文件 `0600`。最后输出服务器主机指纹。链接可以重复使用，删除密钥记录后失效；已安装在远程机器上的公钥需要在远程机器移除。

填写机器地址和 SSH 用户，在管理台点击 **连接并获取指纹**。探测会在取得服务器主机公钥后停止，不进行用户认证。核对所显示的 SHA256 指纹后，点击“确认指纹并添加主机”。也可直接填写通过其他可信方式核对过的指纹。之后连接必须匹配保存的指纹。

Docker Compose 默认挂载一个空的只读密钥卷。使用宿主机目录时在 `.env` 设置：

```sh
SSHHUB_KEYS_MOUNT=/opt/ssh-hub/keys
```

容器 UID/GID 为 `10001:10001`。确保挂载目录可被此用户进入、私钥可读（例如文件归属 UID 10001 且权限 `0600`）。不要把整个宿主机 `.ssh` 目录或其他凭据目录当作管理台可读目录。

备份整个 `/data`，包括 `master.key`、`state.json`、`keys/` 和 `audit/`；挂载的私钥单独备份。

## 客户端机器权限、审批和审计

在“OAuth 客户端”中为每个客户端勾选允许访问的机器，并保存。机器列表和执行入口都会检查权限；猜测其他机器 ID 不能绕过限制。新注册客户端默认没有机器权限，且要求审批。

升级前已有的客户端首次启动时会迁移为“仅允许当时已有的机器 + 需要审批”；以后新增机器不会自动授予这些客户端。可以在管理台修改范围，或关闭指定客户端的逐次审批。

开启审批时，`ssh_exec` 返回 `pending` 和 `session_id`，此时尚未建立 SSH 连接。在管理台“待审批的 SSH 请求”核对客户端、机器和完整命令，再批准或拒绝。批准只对该条请求有效，执行前会重新检查客户端权限和机器配置。10 分钟未处理会过期。使用 `ssh_session_status` 查询结果，避免重新提交同一命令。关闭审批的客户端同步执行，但仍完整审计。

每次 `ssh_exec` 是一个独立 SSH 会话，不是交互式终端。`/data/audit` 以每会话一个 JSON 文件保存客户端、目标、原始命令、审批人、时间、状态、标准输出、标准错误和退出码。输出每秒写入一次，结束时再保存；各输出上限为 512 KiB。写入初始审计失败时禁止连接，执行中写入失败会关闭连接。重启时未完成的请求标记为中断，不自动重放；已启动的远程进程可能仍继续运行。

管理台支持按页查看记录和完整输出，客户端只能查询自己的会话。记录仅管理员可读，不自动清理；命令和输出可能包含业务敏感内容，应一并管理数据卷访问和存储空间。

## 远程 Agent 登录（无需复制 localhost 回调）

服务支持 RFC 8628 设备授权。使用自带 CLI，在远程终端发起登录，浏览器打开显示的链接并确认设备码；终端自动领取令牌，不监听本机回调端口。

构建二进制（Go 1.25，使用仓库内依赖）：

```sh
go build -mod=vendor -o ssh-hub ./cmd/ssh-hub
./ssh-hub login --url https://your-host.example --profile remote-agent
```

随后将 Agent 的 MCP **stdio** 命令配置为：

```sh
/path/to/ssh-hub mcp --url https://your-host.example --profile remote-agent
```

`login` 与 `mcp` 必须在同一系统用户下使用相同 URL 和 profile。不同 Agent 可使用不同 profile，分别获得客户端身份、机器权限和审批策略。凭据默认放在用户配置目录下的 `ssh-hub`（Linux 通常为 `~/.config/ssh-hub`），权限 `0600`；可通过 `SSHHUB_CREDENTIALS_DIR` 改目录。CLI 自动刷新令牌，并用文件锁串行化多进程的 refresh-token 轮换。需要重新授权时运行同样的 `login` 命令并加 `--force`。转发失败不会自动重试执行命令，避免重复操作。

也可以使用 Docker，无需安装 Go：

```sh
docker run --rm -it -v ssh-hub-agent:/data -e SSHHUB_CREDENTIALS_DIR=/data/client \
  ghcr.io/jungoudai/ssh-hub:latest login --url https://your-host.example --profile remote-agent

docker run --rm -i -v ssh-hub-agent:/data -e SSHHUB_CREDENTIALS_DIR=/data/client \
  ghcr.io/jungoudai/ssh-hub:latest mcp --url https://your-host.example --profile remote-agent
```

stdio 模式不要使用 `-t`。私有 GHCR 包首次拉取前需要有读取权限的 Docker 登录。

原生只支持浏览器回调的 MCP 客户端不会自动切换设备码流程；使用上述 stdio 入口可以避免它的 localhost 回调问题。ChatGPT 仍可直接连接 HTTPS `/mcp`，使用现有授权码 + PKCE 流程。

服务端设备授权端点为 `POST /oauth/device/code`、`GET/POST /oauth/device/verify`；令牌端点接受 `urn:ietf:params:oauth:grant-type:device_code`。动态客户端注册时声明该 grant type，可不提供 redirect URI。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SSHHUB_LISTEN_ADDR` | `:8080` | HTTP 监听地址 |
| `SSHHUB_DATA_DIR` | Docker 中的 `/data` | 持久化数据目录 |
| `SSHHUB_KEYS_DIR` | `/keys` | 允许引用的挂载私钥目录 |
| `SSHHUB_KEYS_MOUNT` | `ssh-hub-keys` | Compose 挂载来源，可设置为宿主机绝对目录 |
| `SSHHUB_CREDENTIALS_DIR` | 用户配置目录下的 `ssh-hub` | CLI 的客户端凭据目录 |
| `SSHHUB_PUBLIC_URL` | `http://localhost:8080` | OAuth 发现和资源绑定所用的公网源站地址 |
| `SSHHUB_ADMIN_URL` | 未设置 | 可选的独立管理入口源站；用于管理域名访问和第三方 IdP 回调 |
| `SSHHUB_ADMIN_PASSWORD` | 未设置 | 可选的首次管理员密码，至少 12 个字符 |
| `SSHHUB_OIDC_ISSUER` | 未设置 | OIDC issuer URL；应支持 `/.well-known/openid-configuration` |
| `SSHHUB_OIDC_CLIENT_ID` | 未设置 | 在身份提供方注册的客户端 ID |
| `SSHHUB_OIDC_CLIENT_SECRET` | 未设置 | 在身份提供方注册的客户端密钥 |
| `SSHHUB_OIDC_ALLOWED_EMAILS` | 未设置 | 允许登录的已验证邮箱，多个值用逗号分隔 |
| `SSHHUB_OIDC_ALLOWED_SUBJECTS` | 未设置 | 允许登录的精确 OIDC `sub` 值，多个值用逗号分隔 |
| `SSHHUB_OIDC_LABEL` | `使用第三方账号登录` | 登录页面上的 IdP 按钮文字 |

服务镜像构建后标记为 `ssh-hub:local`。Docker 构建使用仓库内的 Go 依赖，不需要在构建容器中访问 Go 模块代理。

## 验证

```sh
go test -mod=vendor -race ./...
go vet -mod=vendor ./...
# 可选：真实浏览器验证授权表单和管理页面流程
SSHHUB_TEST_CHROMIUM=/usr/bin/chromium go test -mod=vendor ./cmd/ssh-hub -run TestBrowser -v
```

集成测试会启动本地临时 SSH/HTTP 服务器，不使用生产凭据或远程主机。

OAuth 授权、设备码申请、令牌兑换和刷新均可省略 `resource` 参数；首次授权默认绑定本服务 `/mcp`，兑换和刷新继承原授权的资源。显式传入的资源仍需匹配，访问令牌的资源校验保持启用。

# PDF 资源库配置

资源页位于 `/resources/`，在线阅读器位于 `/resources/view/`。PDF 使用 Vercel Blob 公共存储，游客可以在线预览和下载；上传与删除仅对 GitHub 用户 ID `180516193` 开放。

## 1. 连接 Vercel Blob

1. 打开 Vercel 项目，进入 **Storage**。
2. 创建 Blob store，并连接到当前项目。
3. Vercel 会自动写入 `BLOB_READ_WRITE_TOKEN`。生产环境和预览环境按需要启用。

## 2. 创建 GitHub OAuth App

在 GitHub 的 **Settings > Developer settings > OAuth Apps** 中创建 OAuth App：

- Application name: `seadream resources`
- Homepage URL: `https://seadream.vercel.app`
- Authorization callback URL: `https://seadream.vercel.app/api/auth/callback`

创建后取得 Client ID，并生成 Client Secret。OAuth 仅申请 `read:user`，用于读取登录账号的固定 GitHub 用户 ID；GitHub access token 在验证完成后立即丢弃，不写入 Cookie 或数据库。

## 3. 配置 Vercel 环境变量

在项目的 **Settings > Environment Variables** 中添加：

```text
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
AUTH_SECRET=至少 32 位的随机字符串
GITHUB_OAUTH_CALLBACK_URL=https://seadream.vercel.app/api/auth/callback
```

可用下面的命令生成 `AUTH_SECRET`：

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

修改环境变量后重新部署。Client Secret、`AUTH_SECRET` 和 Blob Token 不得提交到 Git。

## 4. 本地开发

将 `.env.example` 复制为 `.env`，填入本地测试值。GitHub OAuth App 的回调地址必须与本地地址一致；若生产 OAuth App 只登记了线上回调，可另建一个仅用于本地开发的 OAuth App。

```powershell
pnpm dev
```

## 限制与行为

- 单个 PDF 最大 500 MiB。
- 大于等于 100 MiB 时自动使用分片上传。
- 服务端检查 Content-Type 和 PDF 文件头，拒绝伪装文件。
- PDF 使用不可变路径和一年缓存；资源列表使用短时 CDN 缓存。
- 管理会话为 HttpOnly、SameSite=Lax 的 12 小时签名 Cookie。

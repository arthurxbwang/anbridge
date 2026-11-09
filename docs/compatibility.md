# AllinSSL 协议兼容范围

核查日期：2026-11-09。

参考来源：

- acbridge：https://github.com/arthurxbwang/acbridge
- AllinSSL 1.1.4 SafeLine 部署源码：
  https://github.com/allinssl/allinssl/blob/1.1.4/backend/internal/cert/deploy/safelinewaf.go
- Nginx 命令参数：https://nginx.org/en/docs/switches.html
- Nginx 重载语义：https://nginx.org/en/docs/control.html

ANBridge 是新实现；参考 acbridge 的兼容思路，没有复制其 Caddy 部署后端。
API 测试复现上述 AllinSSL 代码的请求/响应约定。
尚未启动真实 AllinSSL 面板进行 UI 端到端联调，不能将“协议测试通过”解释为所有 AllinSSL 版本均已验证。

## 支持的协议

认证头：`X-SLCE-API-TOKEN`。没有默认 Token。
响应始终为 JSON，必须含字符串 `msg`；成功时 `msg` 是空字符串。

| 方法与路径 | 行为 |
| --- | --- |
| `GET /api/open/site/group` | 测试连接，仅返回当前身份的站点占位组 |
| `POST /api/open/cert` | 校验证书，暂存；不更换正在运行的证书 |
| `PUT /api/open/system` | 以暂存 ID 请求部署，完成实际 TLS 验证后返回 |
| `GET /api/open/system` | 返回该身份绑定站点的提交状态与 pending 状态 |
| `GET /healthz` | 无认证的进程存活检查；不表示 Nginx 或业务站点健康 |

上传请求：

```json
{"type":2,"crt":"<PEM full chain>","key":"<PEM private key>"}
```

上传响应：

```json
{"data":123456789,"msg":""}
```

`data` 必须是数字，不能改成 `{"id":123456789}`。
AllinSSL 参考实现把 JSON 数字解析成 float64，因此 ID 限制在 `1 .. 2^53-1`。
生成的 ID 是随机值，但访问控制依赖 Token 与本地站点映射，不依赖 ID 难以猜测。

绑定请求：

```json
{"cert_id":123456789}
```

绑定失败返回非 2xx 状态与非空 `msg`。详细的本机路径和 Nginx 输出只写本地日志，
管理 API 返回简短说明。上传错误不会回显私钥或原始请求。

## 在 AllinSSL 中配置

1. 新建雷池 WAF 部署授权，填写 ANBridge 的 **HTTPS 基地址** 和对应站点 Token。
2. 基地址是 `https://bridge-host.example.com:9443` 这类 origin，不加 API 路径前缀。
   AllinSSL 参考实现会重新构建接口路径；不要依赖不同 URL 子路径区分站点。
3. `skip_tls_verify` 保持关闭。让 AllinSSL 信任接收器证书签发机构并使用正确主机名。
4. 部署选择 **面板**，不要选择站点部署。本项目没有实现雷池 site API。
5. 一台主机多个目标时，为每个目标配置不同 Token 和相应的 AllinSSL 部署授权。
6. 测试连接后推送一张覆盖全部目标域名的证书，再检查绑定结果和状态接口。

调用超时后，部署可能仍在帮助进程中完成。先检查本地日志/状态，再重复绑定或重新推送。
默认命令/探测超时是 10 秒；真实操作耗时受 Nginx 和目标主机影响。
请核对所用 AllinSSL 版本的请求超时，不能以客户端超时作为取消部署机制。

## 不兼容范围

- 雷池站点创建、修改、证书删除和通用面板管理。
- 在上传体中提交目标路径、任意命令或 Nginx 配置。
- 同一个 Token 管理多个互不相关的站点。
- 未经目标版本测试便假定后续 AllinSSL 修改仍兼容。

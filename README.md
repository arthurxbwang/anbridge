# ANBridge

AllinSSL → HTTPS → 本机受限部署 → Nginx 平滑重载与证书验证。

ANBridge 让 AllinSSL 通过兼容雷池面板部署的接口更新指定 Nginx 站点的证书，
不向证书中心提供 SSH 登录，不提供远程 Shell 或通用 Nginx 配置接口。
这是首版开发实现，适合先在隔离环境和一个明确站点上验证。

## 已实现

- HTTPS 接收器与 Unix Socket 部署帮助进程分离；接收器必须以非 root 用户运行。
- 一个 Token 对应一个本机目标，固定域名、证书引用位置和本机 TLS 探测端点。
- 完整证书链、私钥配对、有效期、域名与信任根校验。
- 暂存上传与正式绑定分离；数字证书 ID 兼容参考 AllinSSL 实现。
- 不可变证书版本、原子切换专用 include、事务日志和全局部署互斥。
- `nginx -t`、平滑 reload、全新 SNI/TLS 连接验证。
- 相同版本幂等部署；失败回退；启动时恢复未完成事务。
- JSON 日志、配额和请求大小限制、部署状态接口。

## 构建与测试

要求 Go 1.27 或以上（生产构建应使用组织批准且仍维护的工具链）。
可执行程序仅使用 Go 标准库。真实集成测试另外需要可执行的 Nginx。

```bash
cd /root/anbridge
make check
make test
make integration NGINX_BIN=/usr/sbin/nginx
make build
make units
./bin/anbridge version
```

开发环境中的 Go、Nginx 如已解包到 `.tools/sysroot`，Makefile 会优先使用它们。
本次提供的构建使用 Go 1.27.3，模块声明使用 Go 1.27 的默认行为。
在 Debian 13 上可用 `python3 scripts/dev-tools.py` 获取项目内工具：
Go 来自已验证 Release 签名及 SHA-256 的 backports 元数据，Nginx 按本机 APT 元数据校验。
此脚本只解包到项目目录，不安装系统包。
所有构建缓存和测试临时文件位于项目的 `.cache`、`.tmp` 内。
`make test` 包含 race 检测；真实 Nginx 测试需要显式运行 `make integration`，
否则该测试会明确跳过。

集成测试使用随机本机端口、临时 CA、临时证书和项目内独立 Nginx 配置，
不使用宿主机 Nginx 服务。它实际经过 HTTPS 接口和本机 Unix Socket，验证新证书生效、
重复请求、配置检查失败，以及重载成功但目标仍提供旧证书时的回退。

构建产物：`bin/anbridge`。执行 `sh scripts/package.sh` 可生成 Linux amd64 分发包，
包含二进制、配置示例、服务文件和文档，不包含任何真实 Token 或私钥。

## 首次部署

完整步骤见 [部署与运维](docs/operations.md)，包括：

1. 安装独立用户、二进制、管理接口 HTTPS 证书、每站点 Token。
2. 修改 [配置示例](configs/anbridge.example.json)，核对实际 Nginx 路径、域名及回环探测。
3. 用 `bootstrap` 导入当前有效证书作为回退基线。
4. 将站点证书引用改为专用 include，手动完成首次检查与重载。
5. 安装并启动 [systemd 服务](deploy/systemd/)。
6. 在 AllinSSL 选择“雷池 WAF → 面板部署”，完成连接测试和一次真实续期演练。

配置和命令中的示例域名必须替换。API 默认监听 `127.0.0.1:9443`；
远程 AllinSSL 需要管理网监听地址及对应访问控制。

## 文档

- [架构、权限和事务边界](docs/architecture.md)
- [AllinSSL 协议与配置](docs/compatibility.md)
- [部署、日志、轮换与故障恢复](docs/operations.md)
- [验证记录与尚未验证的范围](docs/validation.md)

## 验证边界

AllinSSL 参考协议来自 1.1.4 的部署代码，已用协议合同测试覆盖；
尚未在实际 AllinSSL 面板中执行端到端操作。
真实 Nginx 集成测试与目标 VM 的 systemd 部署是不同验证层次。
首版不管理容器、不部署到远程 Nginx、不提供双 RSA/ECDSA 证书组合或 Web 控制台。

管理接口自身的 HTTPS 证书不由本项目自动续期；通过既有可信渠道维护并重启接收器。
部署与状态目录包含私钥，应使用受限权限并纳入受控备份。

# 部署与运维

下面的安装命令供**目标服务器**使用；开发测试不会自动执行它们。
首次安装需要管理员权限，此后 AllinSSL 不需要 SSH 登录。

## 1. 准备

需要：

- Linux、systemd、已正常运行的 Nginx。
- 当前业务站点的一张有效证书及私钥，用作初始回退基线。
- 独立的 ANBridge HTTPS 管理域名/证书，AllinSSL 能验证其证书链。
- 本机回环地址可连接业务 TLS 端口；例如现有 `listen 443 ssl` 包含回环监听。
  若仅监听特定网卡，应在对应 server 块增加受控的回环监听。

先查看目标服务器的 `nginx -V`，确认实际二进制、配置、prefix 和日志/临时路径。
示例使用 `/usr/sbin/nginx`、`/etc/nginx/nginx.conf`、`/usr/share/nginx`；
自编译版本可能不同。

## 2. 安装文件

以下以构建产物 `bin/anbridge` 和仓库文件为来源：
若使用分发包，解压目录中的二进制是 `./anbridge`，相应替换安装命令的源路径。

```bash
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin anbridge
sudo install -m 0755 bin/anbridge /usr/local/bin/anbridge
sudo install -d -o root -g anbridge -m 0750 /etc/anbridge /etc/anbridge/tokens /etc/anbridge/tls
sudo install -d -o root -g root -m 0750 /etc/nginx/anbridge
sudo install -o root -g anbridge -m 0640 configs/anbridge.example.json /etc/anbridge/config.json
sudo install -m 0644 deploy/systemd/anbridge-api.service /etc/systemd/system/anbridge-api.service
sudo install -m 0644 deploy/systemd/anbridge-deploy.service /etc/systemd/system/anbridge-deploy.service
```

若用户已存在，跳过 useradd。不要使用 `/root` 下的项目路径作为生产配置或密钥路径；
服务文件启用了 `ProtectHome=true`。

编辑 `/etc/anbridge/config.json`，设置实际域名和站点：

- `listen` 默认回环。AllinSSL 在其他主机时改为本机管理网 IP，并限制入口来源。
- 配置中域名填写实际具体域名。证书可以是覆盖它们的通配符证书。
- `probes` 每个域名至少一项，地址使用 `127.0.0.1:<port>` 或 `[::1]:<port>`。
- 内部 CA 业务证书设置站点 `ca_file`，文件由 root 管理，接收器可以读取。
- 管理接口 TLS 与业务证书是两个用途。管理接口使用正确匹配主机名的完整证书链。
- 自定义 include、数据、日志目录时，同时调整 systemd 的可写路径与服务依赖。

安装管理接口证书和私钥到配置的 `tls` 路径，属主 `root:anbridge`，
私钥权限 `0640`，目录 `0750`。不要把私钥放进代码仓库。

生成站点 Token，写入文件而不在命令输出中显示：

```bash
sudo sh -c 'umask 027; openssl rand -hex 32 > /etc/anbridge/tokens/zabbix'
sudo chown root:anbridge /etc/anbridge/tokens/zabbix
sudo chmod 0640 /etc/anbridge/tokens/zabbix
sudo /usr/local/bin/anbridge check-config -config /etc/anbridge/config.json
```

`check-config` 检查结构和范围；不等于现场证书、权限和网络均已验收。

## 3. 导入当前工作证书

```bash
sudo /usr/local/bin/anbridge bootstrap \
  -config /etc/anbridge/config.json \
  -site zabbix \
  -cert /path/to/current/fullchain.pem \
  -key /path/to/current/privkey.pem
```

路径必须替换为现有文件。输入文件需要是普通文件；若原证书使用 Certbot 等工具的符号链接，
先用 `readlink -f` 得到实际文件路径，再传给 bootstrap。
bootstrap 会验证并保存基线，创建专用 include。
它不修改其他 Nginx 配置、不执行 reload，也不覆盖已有基线/include。

在对应 `server { ... }` 中，将原来的这一组证书指令替换为：

```nginx
include /etc/nginx/anbridge/zabbix.conf;
```

保留其他业务配置。不要同时保留重复的原证书指令或引用错误站点。
按照配置中的相同 prefix/config 执行检查和重载，再验证业务站点的证书。
这是首次接入时的一次管理员操作。

## 4. 启动

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now anbridge-deploy.service anbridge-api.service
sudo systemctl status anbridge-deploy.service anbridge-api.service
```

帮助进程启动时先处理未完成事务，再开放 Socket。
默认示例需要发行版 `nginx.service`；使用其他服务名称时修改 Unit。
API 进程拒绝以 root 运行。

两套服务的状态目录与权限由 systemd 创建。Unix Socket 位于 root 控制的目录，
只授权 `anbridge` 组访问。帮助进程的可写范围包含证书 include、状态目录以及常规
Nginx 日志/临时目录及实际 PID 文件。`nginx -t` 也会以读写方式打开 PID 文件，
因此示例授权 `/run/nginx.pid`；不同发行版必须相应调整。
服务用 `PartOf` 在 Nginx 重启时一起重启，更新 PID 文件的隔离挂载。
若 nginx -t 出现只读文件系统/权限错误，
核对真实路径和 systemd 约束，不要直接去掉全部隔离措施。

然后按 `compatibility.md` 配置 AllinSSL 授权与面板部署。

## 5. 日常操作

```bash
sudo journalctl -u anbridge-api -u anbridge-deploy --since today
sudo systemctl restart anbridge-api
```

- 更换 Token 或管理 HTTPS 证书后重启 API 服务，Nginx 不需要因此重启。
- 修改目标、CA、路径、Nginx 参数后，先校验配置，再有序重启两服务。
- `/healthz` 只检查接收器存活。业务 TLS、有效期和帮助进程状态需另设监控。
- 认证的 `GET /api/open/system` 返回当前身份站点的提交状态；`verified_at` 是
  上次成功部署/检查时间，不表示系统一直在后台持续探测业务端口。
- 上传占用的暂存证书默认 48 小时过期，过期 ID 不再允许绑定；到期文件在下一次上传清理。
- 状态、所有仍被引用的版本、include、配置和 Token 应做受限备份。
- 版本目录默认保留。清理历史版本前确认它既不是 active，也不是 pending 的 previous/next。

## 6. 故障恢复

**AllinSSL 返回失败或超时**：先看该站点状态与本地日志。超时不一定表示未部署。
重复绑定同一未过期 ID 是允许的；重新上传同一证书也不会在真实证书已生效时多次 reload。

**nginx -t 失败**：ANBridge 恢复旧 include，旧 Nginx 通常继续运行。
修复实际配置错误后再重试。不要通过绕过校验强制宣布成功。

**探测仍看到旧证书**：检查对应 server 是否实际使用受管理的 include、回环监听、
SNI、证书链和 CA。成功执行 reload 不足以证明目标虚拟主机已换证书。

**出现 pending 且回退失败**：

1. 暂停 AllinSSL 对该目标的重复部署，查看帮助进程日志。
2. 检查磁盘、配置、监听端口和旧版本文件是否完整。
3. 修复环境后重启帮助进程，它会按 pending 记录恢复旧版本并验证。
4. 只有确认恢复完成后才恢复推送。不要直接删除 pending 或编辑其版本 ID 来消除报错。

**新证书已提供，但状态提交报错**：最后的状态文件替换可能已完成、也可能未完成。
ANBridge 不会因此盲目切回旧配置，也不会报告部署成功。先处理存储问题，
再根据状态或重启恢复结果处理；不要把“请求失败”直接等同于“线上仍是旧证书”。

**首次 bootstrap 中断**：若 include 已写入但 state 未建立，服务不会自动覆盖它。
先确认业务引用和当前证书，保留现场备份后再整理初始文件并重新 bootstrap。
这一步属于首次接入，不具备既有已提交版本可自动恢复。

所有服务文件和权限说明都需要在目标发行版实际验证。
本项目的隔离测试不等同于已在目标 VM 的 systemd、SELinux/AppArmor 和防火墙策略下部署。

# 独立 SSH 服务脚本

`ssh-serve.py` 在 Linux 上启动独立 SSH 服务，配置、密钥和日志保存在专用目录。不修改 `.ssh` 或系统 SSH 配置，不重启系统服务，不设置开机自启。

支持直连（forward）和反向隧道（reverse）。下文 A 为运行脚本的机器，B 为中转机，客户端为执行登录命令的电脑。示例用户名和地址均需替换。

默认在前台持续运行，Python 管理 `sshd` 和反向隧道 `ssh` 的生命周期，不会自行转入后台。需要后台运行时可自行使用 tmux 或 nohup。

## 环境要求与下载

需要 Linux、Python 3.7+ 和 OpenSSH（`sshd`、`ssh`、`ssh-keygen`、`ssh-keyscan`）；reverse 模式的客户端需支持 `ssh -J`。

```bash
curl -fsSLO https://scripts.gbdj.cc/ssh-serve.py
python3 ssh-serve.py --help
```

reverse 需要交互输入，请下载后执行，不要使用 `curl ... | python3`。

## 用法

```text
python3 ssh-serve.py [-h] [-v] [-u USER] [-k KEY] [-d DIR] [-m MODE] [-p PORT]
```

| 参数 | 说明 |
| --- | --- |
| `-h`、`--help` | 显示帮助并退出 |
| `-v`、`--version` | 显示版本号并退出 |
| `-u`、`--user` | 登录 A 的用户，默认是运行脚本的有效用户；普通用户只能指定自己 |
| `-k`、`--key` | 登录 A 的公钥，或 `@/path/key.pub`；可重复 |
| `-d`、`--dir` | 专用目录，默认 `/tmp/extra-sshd` |
| `-m`、`--mode` | `forward`（默认），或 `reverse:B用户@B地址:B的SSH端口` |
| `-p`、`--port` | forward 为 A 端口，reverse 为 B 隧道端口；默认自动分配 |

`-k @路径` 读取 A 上的单条公钥文件，不支持 `authorized_keys` options；新增公钥会追加，已有授权会保留。

## 简单示例

### 1. 直接启动，自动选择端口

在 A 上执行：

```bash
python3 ssh-serve.py
```

首次运行未指定公钥时，将生成的 `/tmp/extra-sshd/client_ed25519` 安全复制到客户端，按输出的端口登录：

```bash
# 在客户端执行；替换端口、用户名和 A 地址
chmod 600 ./client_ed25519
ssh -i ./client_ed25519 -o IdentitiesOnly=yes -p 2222 appuser@A地址
```

forward 监听 `0.0.0.0`，需放行防火墙端口；有 NAT 时配置端口映射，使用实际可达的地址和端口。

### 2. 指定端口，使用客户端已有密钥

将客户端公钥（例如 `~/.ssh/id_ed25519.pub`）复制到 A 的 `/tmp/my-client.pub`，然后在 A 上执行：

```bash
python3 ssh-serve.py -p 2222 -k @/tmp/my-client.pub
```

客户端使用自己保留的对应私钥登录：

```bash
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -p 2222 appuser@A地址
```

### 3. 用 sudo 启动，但以普通用户登录

```bash
sudo python3 ssh-serve.py -u appuser -p 2222 -d /tmp/extra-sshd-root -k @/tmp/my-client.pub
```

将 `appuser` 替换为实际普通用户。**sudo 启动未指定 `-u` 时，远程登录身份默认为 root**。指定普通用户后，其 sudo 权限不变。切换运行用户时使用各自的 `-d` 目录。

### 4. 通过 B 建立反向隧道

在 A 上执行，将 B 的地址和用户替换为实际值：

```bash
python3 ssh-serve.py -m reverse:relay@B地址:22 -p 22022 -k @/tmp/my-client.pub
```

脚本会提示选择 A 登录 B 的认证方式：

- **密码**：由 SSH 提示输入 B 用户的密码，脚本不保存密码。
- **密钥（默认）**：脚本显示 A 的公钥，需要将它加入 B 上 `relay` 用户的 `authorized_keys`，再按回车继续。

B 的 SSH 服务需要允许远程端口转发，且 `22022` 端口可用。省略 `-p` 可自动分配 B 上的隧道端口。

A 的服务和 B 的隧道端口均监听 `127.0.0.1`，客户端通过 B 跳转到 A：

```bash
# 在客户端执行；私钥对应上面 /tmp/my-client.pub 的公钥
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes \
  -J relay@B地址:22 -p 22022 appuser@127.0.0.1
```

`-i` 指定登录 A 的私钥。客户端还需具备登录 B 的凭据：使用 B 的密码，或在客户端 `~/.ssh/config` 中为 B 配置 `IdentityFile`。A 连接 B 的密钥不会自动用于客户端连接 B。

## 密钥与授权

| 文件 | 用途 |
| --- | --- |
| `host_ed25519` / `.pub` | A 的主机密钥，对应输出的主机指纹 |
| `client_ed25519` / `.pub` | 默认登录密钥，也用于 A 连接 B |
| `authorized_keys` | 允许登录 A 的公钥 |
| `known_hosts` | B 的主机身份 |

未指定 `-k` 且无已有授权时，脚本将 `client_ed25519.pub` 加入 A 的授权列表，客户端使用对应私钥登录。指定 `-k` 则使用对应的客户端私钥；脚本仍生成或复用 `client_ed25519`，用于 reverse 密钥认证。

**默认登录 A 和 A 连接 B 会复用同一套密钥。** 使用客户端自有密钥时，只将公钥交给 A。私钥不要公开，权限设为 `600`。连接 A 时核对输出的主机指纹；reverse 密钥认证首次连接 B 会自动记录其主机密钥，后续不匹配则拒绝连接。

## 日志、停止与再次启动

默认目录 `/tmp/extra-sshd` 保存配置和日志，`state.json` 记录 Python、sshd、隧道（reverse 模式）的 PID、模式和端口。这是启动信息快照，不能用来判断服务是否仍在运行。

查看日志：

```bash
tail -n 50 /tmp/extra-sshd/sshd.log
```

在前台按 `Ctrl+C` 停止，或使用启动输出中的 Python PID：

```bash
kill <Python PID>
```

Python 退出会同时停止本次启动的 sshd 和反向隧道；任一服务异常退出也会停止另一服务。Linux 父进程死亡信号确保即使 Python 被 `kill -9`，这两个直接子进程也会被内核终止。sudo 启动的服务需相应权限才能停止。

这管理的是监听服务和隧道进程；已登录 SSH 会话中另行创建或脱离的进程不属于这一保证。

需要后台运行时，例如：

```bash
tmux new -s extra-sshd 'python3 ssh-serve.py'
# 或用于无需交互的 forward 模式
nohup python3 ssh-serve.py >extra-sshd.out 2>&1 &
```

再次启动前先停止同目录的服务与隧道，或用不同的 `-d` 目录。停止不会删除密钥，再次启动会复用密钥和授权；需长期保留时，选择 `/tmp` 以外的专用目录。

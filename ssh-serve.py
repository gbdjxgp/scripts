#!/usr/bin/env python3
"""独立 SSH 服务：无需改 .ssh 或重启；普通用户只能提供自己的登录服务。
依赖：Linux、Python 3.7+、OpenSSH sshd/ssh/ssh-keygen/ssh-keyscan。
reverse 模式把端口绑定到 B 的 127.0.0.1，通过 ssh -J 访问。
"""
import argparse
import ctypes
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

VERSION = '1.1.0'


def start_managed(cmd, **kwargs):
    """Linux：即使 Python 被 SIGKILL，直接子进程也由内核终止。

    本脚本为单线程；preexec_fn 中只设置 prctl 并检查 fork/父进程退出竞态。
    """
    parent = os.getpid()
    libc = ctypes.CDLL(None, use_errno=True)

    def bind_parent():
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            os._exit(127)
        if os.getppid() != parent:
            os._exit(127)

    return subprocess.Popen(cmd, preexec_fn=bind_parent, **kwargs)


def stop_managed(process):
    if process is not None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        process.wait()


def handle_signal(signum, frame):
    raise SystemExit(128 + signum)


def fail(message):
    raise RuntimeError(message)


def run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def atomic_write(path, text):
    fd, name = tempfile.mkstemp(prefix='.extra-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        os.replace(name, str(path))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def config_quote(value):
    # OpenSSH 展开路径中的 % 标记；%% 表示字面量 %。
    return '"' + str(value).replace('%', '%%').replace('\\', '\\\\').replace('"', '\\"') + '"'


def command(args):
    return ' '.join(shlex.quote(str(part)) for part in args)


def tool(name):
    found = shutil.which(name)
    if not found and name == 'sshd' and Path('/usr/sbin/sshd').is_file():
        found = '/usr/sbin/sshd'
    if not found:
        fail('缺少命令 %s；请安装对应的 OpenSSH 包。' % name)
    return str(Path(found).resolve())


def parse_mode(value):
    if value == 'forward':
        return None
    match = re.fullmatch(r'reverse:([^@\s:]+)@(\[[^\]\s]+\]|[^:\s]+):(\d+)', value)
    if not match:
        raise argparse.ArgumentTypeError('格式：forward 或 reverse:user@host:port；IPv6 用 [地址]')
    user, host, port = match.groups()
    if user.startswith('-') or host.startswith('-') or not 1 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError('无效的 B 用户、地址或 SSH 端口')
    return user, host.strip('[]'), int(port)


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
    p.add_argument('-u', '--user', default=pwd.getpwuid(os.geteuid()).pw_name,
                   help='A 的登录用户，默认当前有效用户；非 root 不能指定其他用户')
    p.add_argument('-k', '--key', action='append', default=[],
                   help='信任的完整公钥，可重复；也支持 @/path/key.pub')
    p.add_argument('-d', '--dir', default='/tmp/extra-sshd', help='专用目录，默认 /tmp/extra-sshd')
    p.add_argument('-m', '--mode', type=parse_mode, default='forward',
                   help='forward（默认）或 reverse:user@host:port')
    p.add_argument('-p', '--port', type=int, help='forward 为 A 端口，reverse 为 B 端口；省略则自动分配')
    return p


def prepare_directory(raw):
    expanded = os.path.expanduser(raw)
    if expanded.startswith('~') or any(c in expanded for c in '\r\n\x00'):
        fail('无法解析目录。')
    path = Path(os.path.abspath(expanded))
    # /tmp 是合法父目录；要求公共可写父目录有 sticky bit，并拒绝符号链接。
    for part in [path] + list(path.parents):
        if part.is_symlink():
            fail('目录路径不能含符号链接：' + str(part))
        if part.exists():
            s = part.stat()
            if not stat.S_ISDIR(s.st_mode):
                fail('路径不是目录：' + str(part))
            if part == path:
                if s.st_uid != os.geteuid() or s.st_mode & 0o066:
                    fail('已有专用目录必须属于当前用户且权限为 700（跨用户 root 服务可为 711）：' + str(part))
            elif s.st_mode & 0o022 and not s.st_mode & stat.S_ISVTX:
                fail('父目录可被其他用户改写：' + str(part))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.name in {'setup.lock', 'host_ed25519', 'host_ed25519.pub', 'authorized_keys',
                          'sshd_config', 'sshd.pid', 'sshd.log', 'client_ed25519',
                          'client_ed25519.pub', 'reverse_ed25519', 'reverse_ed25519.pub',
                          'known_hosts', 'state.json', 'reverse.sock'}:
            if child.is_symlink() or child.stat().st_uid != os.geteuid():
                fail('管理文件必须属于当前用户且不能是符号链接：' + str(child))
            if child.name != 'reverse.sock' and not child.is_file():
                fail('管理文件必须为普通文件：' + str(child))
    lock = open(str(path / 'setup.lock'), 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return path, lock


def keypair(path, keygen):
    pub = Path(str(path) + '.pub')
    if path.exists():
        if path.stat().st_mode & 0o077:
            fail('已有私钥权限须为 600：' + str(path))
        result = run([keygen, '-y', '-P', '', '-f', str(path)], capture_output=True, text=True)
        if not pub.exists() or pub.read_text().split()[:2] != result.stdout.split()[:2]:
            atomic_write(pub, result.stdout)
    else:
        if pub.exists():
            fail('只有公钥，没有匹配私钥；保留文件并退出：' + str(pub))
        run([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', str(path)])
    return pub.read_text().strip()


def validate_key(value, keygen):
    if value.startswith('@'):
        value = Path(os.path.expanduser(value[1:])).read_text()
    value = value.strip()
    parts = value.split()
    if '\n' in value or '\r' in value or len(parts) < 2 or not parts[0].startswith(('ssh-', 'ecdsa-', 'sk-')):
        fail('-k 必须是单行完整公钥，不支持 authorized_keys options。')
    with tempfile.TemporaryDirectory() as temporary:
        file = Path(temporary) / 'key.pub'
        file.write_text(value + '\n')
        result = subprocess.run([keygen, '-l', '-f', str(file)], capture_output=True, text=True)
        if result.returncode:
            fail('公钥无效：' + result.stderr.strip())
    return value


def free_port(bind):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((bind, 0))
        return sock.getsockname()[1]


def check_port(bind, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((bind, port))


def local_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(('192.0.2.1', 9))
            return sock.getsockname()[0]
    except OSError:
        return socket.gethostname()


def main():
    args = parser().parse_args()
    if args.port is not None and not 1 <= args.port <= 65535:
        fail('-p 必须在 1..65535 之间。')
    account = pwd.getpwnam(args.user)
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*[$]?', args.user):
        fail('不支持此用户名格式。')
    if os.geteuid() != 0 and account.pw_uid != os.geteuid():
        fail('普通用户只能为自己提供 SSH 登录服务，不能切换为其他用户。')
    if account.pw_shell.endswith(('/nologin', '/false')):
        fail('该用户的 shell 禁止登录。')
    if os.geteuid() != 0 and args.mode is None and args.port is not None and args.port < 1024:
        fail('普通用户请使用 >=1024 的端口，或省略 -p 自动分配。')
    sshd, ssh, keygen, keyscan = [tool(x) for x in ('sshd', 'ssh', 'ssh-keygen', 'ssh-keyscan')]
    directory, lock = prepare_directory(args.dir)
    pidfile = directory / 'sshd.pid'
    if pidfile.exists():
        try:
            old_pid = int(pidfile.read_text().strip())
            if old_pid > 0:
                os.kill(old_pid, 0)
                fail('此目录的 PID 仍存在，请先检查/停止旧服务，或换 -d 目录。')
        except (ValueError, ProcessLookupError):
            pass
    sockpath = directory / 'reverse.sock'
    if sockpath.exists():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control:
            try:
                control.connect(str(sockpath))
            except ConnectionRefusedError:
                sockpath.unlink()  # SIGKILL 后留下的失效 socket。
            else:
                fail('已有反向隧道控制 socket；请先停止旧隧道，或换 -d 目录。')
    if args.mode and len(os.fsencode(str(sockpath))) > 90:
        fail('反向模式目录太长，Unix socket 路径请控制在 90 字节以内。')
    host = directory / 'host_ed25519'
    keypair(host, keygen)
    authorized = directory / 'authorized_keys'
    lines = authorized.read_text().splitlines() if authorized.exists() else []
    keys = [validate_key(k, keygen) for k in args.key]
    # 本机登录密钥的生命周期只由 -d 内文件决定，与 -k 无关。
    login_key = directory / 'client_ed25519'
    login_public = keypair(login_key, keygen)
    generated_client = None
    if not keys and not any(line.strip() and not line.lstrip().startswith('#') for line in lines):
        generated_client = login_key
        keys.append(login_public)
    identities = {tuple(line.split()[:2]) for line in lines if len(line.split()) >= 2}
    for key in keys:
        identity = tuple(key.split()[:2])
        if identity not in identities:
            lines.append(key)
            identities.add(identity)
    atomic_write(authorized, '\n'.join(lines) + '\n')
    if not args.key and tuple(login_public.split()[:2]) in identities:
        generated_client = login_key
    # root 服务登录其他用户时，authorized_keys 必须让该用户可读；公钥本身不是秘密。
    if os.geteuid() == 0 and account.pw_uid != 0:
        os.chmod(str(authorized), 0o644)
        os.chmod(str(directory), 0o711)
    bind = '127.0.0.1' if args.mode else '0.0.0.0'
    port = free_port(bind) if args.mode or args.port is None else args.port
    check_port(bind, port)
    config = directory / 'sshd_config'
    atomic_write(config, '\n'.join([
        'Port ' + str(port), 'AddressFamily inet', 'ListenAddress ' + bind,
        'HostKey ' + config_quote(host), 'PidFile ' + config_quote(pidfile),
        'AuthorizedKeysFile ' + config_quote(authorized), 'AllowUsers ' + args.user,
        'PubkeyAuthentication yes', 'AuthenticationMethods publickey',
        'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
        'PermitEmptyPasswords no', 'PermitRootLogin prohibit-password',
        'UsePAM ' + ('yes' if os.geteuid() == 0 else 'no'),
        # 路径完全受专用目录权限约束；兼容 /tmp 及跨用户 root 启动场景。
        'StrictModes no', 'Subsystem sftp internal-sftp', ''
    ]))
    # 不修改系统运行目录；缺少 privsep 目录时明确报错，由部署者处理。
    checked = subprocess.run([sshd, '-t', '-f', str(config)], capture_output=True, text=True)
    if checked.returncode:
        fail('sshd 配置检查失败：\n' + checked.stderr)
    process = None
    tunnel = None
    try:
        logfile = directory / 'sshd.log'
        with open(str(logfile), 'ab') as log:
            process = start_managed([sshd, '-D', '-e', '-f', str(config)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                       close_fds=True)
        for _ in range(40):
            time.sleep(0.1)
            if process.poll() is not None:
                fail('sshd 启动失败：\n' + logfile.read_text()[-4000:])
            if pidfile.exists() and pidfile.read_text().strip() == str(process.pid):
                break
        else:
            fail('sshd 未在预期时间内就绪：' + str(logfile))
        # ssh-keyscan 完成 SSH 握手，捕获“监听成功但 chroot 等权限不足”的情况。
        probe = subprocess.run([keyscan, '-T', '5', '-t', 'ed25519', '-p', str(port), '127.0.0.1'],
                               capture_output=True, text=True, timeout=8)
        if probe.returncode or not probe.stdout.strip():
            fail('SSH 握手检查失败（可能是容器/系统权限限制）：\n' + logfile.read_text()[-4000:])
        state = {'python_pid': os.getpid(), 'sshd_pid': process.pid,
                 'a_user': args.user, 'a_port': port, 'mode': 'forward'}
        print('本机登录密钥（按目录内容生成或复用）：' + str(login_key))
        identity = ['/你的/客户端私钥']
        if generated_client:
            print('\n使用目录中的默认登录凭据（已有密钥直接复用）。')
            print('请安全复制到客户端，并 chmod 600；不要公开私钥：' + str(generated_client))
            identity = ['./' + generated_client.name]
        final = [ssh, '-i', identity[0], '-o', 'IdentitiesOnly=yes']
        if not args.mode:
            final += ['-p', str(port), args.user + '@' + local_address()]
            print('\nA 监听：0.0.0.0:%d；如有 NAT，请将最终命令中的 IP 改为实际可达 IP。' % port)
        else:
            buser, bhost, bport = args.mode
            dest = buser + '@' + bhost
            print('\n连接 B：%s，SSH 端口 %d' % (dest, bport))
            auth = input('认证方式 [1] 密码 / [2] 密钥（默认 2）：').strip().lower()
            if auth not in ('', '1', '2', 'password', 'key'):
                fail('认证方式请输入 1 或 2。')
            base = [ssh, '-F', '/dev/null', '-p', str(bport),
                    '-o', 'UserKnownHostsFile=' + str(directory / 'known_hosts'),
                    '-o', 'StrictHostKeyChecking=ask', '-o', 'ConnectTimeout=15',
                    '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3']
            if auth in ('1', 'password'):
                base += ['-o', 'PubkeyAuthentication=no',
                         '-o', 'PreferredAuthentications=keyboard-interactive,password']
                print('接下来由 ssh 在终端提示输入 B 的密码；脚本不读取或保存密码。')
            else:
                outgoing = login_key
                public = login_public
                print('\n请让 B 的 %s 用户信任下面的 A 公钥（复用 %s）：' % (buser, outgoing))
                print(public, flush=True)
                input('在 B 上配置好信任后，按回车尝试公钥连接：')
                base += ['-i', str(outgoing), '-o', 'IdentitiesOnly=yes',
                         '-o', 'PreferredAuthentications=publickey', '-o', 'BatchMode=yes']
                # BatchMode 不允许首次主机指纹交互，先单独确认 B 的身份。
                base = [x if x != 'StrictHostKeyChecking=ask' else 'StrictHostKeyChecking=accept-new' for x in base]
                print('首次 B 主机指纹采用 TOFU；若已有指纹不匹配将拒绝连接。')
            master = base + ['-S', str(sockpath)]
            # 先交互认证，再通过 control socket 分配 B 的端口；0 由 B 操作系统分配。
            tunnel = start_managed(master + ['-M', '-N', '-T', dest])
            # 密码认证可能需要较长时间；不限制用户输入时间。
            while not sockpath.exists():
                if tunnel.poll() is not None:
                    fail('反向隧道启动失败，退出码：%d' % tunnel.returncode)
                if process.poll() is not None:
                    fail('sshd 在建立隧道时退出。')
                time.sleep(0.1)
            requested = args.port or 0
            spec = '127.0.0.1:%d:127.0.0.1:%d' % (requested, port)
            forwarded = run(master + ['-O', 'forward', '-o', 'ExitOnForwardFailure=yes', '-R', spec, dest],
                            capture_output=True, text=True)
            exposed = requested
            if requested == 0:
                numeric = [int(line.strip()) for line in forwarded.stdout.splitlines() if line.strip().isdigit()]
                if not numeric:
                    fail('未能解析 B 分配的端口：' + forwarded.stdout + forwarded.stderr)
                exposed = numeric[-1]
            jump_host = ('[' + bhost + ']') if ':' in bhost else bhost
            jump = '%s@%s:%d' % (buser, jump_host, bport)
            final += ['-J', jump, '-p', str(exposed), args.user + '@127.0.0.1']
            state.update(mode='reverse', b_user=buser, b_host=bhost, b_ssh_port=bport,
                         b_port=exposed, control_socket=str(sockpath), tunnel_pid=tunnel.pid)
            print('\nB 监听：127.0.0.1:%d -> A 127.0.0.1:%d' % (exposed, port))
            print('客户端还需能登录 B；A→B 的隧道密钥不会自动授权客户端→B。')
        atomic_write(directory / 'state.json', json.dumps(state, ensure_ascii=False, indent=2) + '\n')
        print('\n访问命令（在客户端执行；-i 替换为对应私钥路径）：\n' + command(final))
        print('A 主机指纹：', flush=True)
        run([keygen, '-l', '-f', str(host) + '.pub'])
        print('Python PID：%d；A 服务 PID：%d；停止：Ctrl+C 或 kill %d' %
              (os.getpid(), process.pid, os.getpid()))
        print('日志：' + str(logfile))
        print('状态：' + str(directory / 'state.json'))
        print('前台运行中；不会修改 .ssh、系统 SSH 配置或设置开机自启。', flush=True)
        while True:
            if process.poll() is not None:
                fail('sshd 已退出，退出码：%d' % process.returncode)
            if tunnel is not None and tunnel.poll() is not None:
                fail('反向隧道已退出，退出码：%d' % tunnel.returncode)
            time.sleep(0.2)
    finally:
        stop_managed(tunnel)
        stop_managed(process)
        if process is not None:
            unlink_if_exists(pidfile)
        if tunnel is not None:
            unlink_if_exists(sockpath)


def unlink_if_exists(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


if __name__ == '__main__':
    os.umask(0o077)
    signal.signal(signal.SIGTERM, handle_signal)
    # nohup 继承的 SIGHUP=SIG_IGN 必须保留。
    if signal.getsignal(signal.SIGHUP) != signal.SIG_IGN:
        signal.signal(signal.SIGHUP, handle_signal)
    try:
        main()
    except KeyboardInterrupt:
        print('\n已取消，本次新启动进程已清理。', file=sys.stderr)
        sys.exit(130)
    except (RuntimeError, OSError, KeyError, ValueError, EOFError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print('错误：' + str(error), file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)

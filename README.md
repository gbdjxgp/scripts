# scripts

需 Linux、Python 3.7+、OpenSSH。

```bash
curl -fsSLO https://scripts.gbdj.cc/extra-sshd.py && bash -c 'python3 extra-sshd.py "$@"' -- -p 2222
```

反向模式：将 `-p 2222` 换为 `-m reverse:user@host:22`。
可加 `-k @公钥路径`；省略则生成密钥。按输出连接。

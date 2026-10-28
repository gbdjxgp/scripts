需 Linux、Python 3.7+、OpenSSH。

```bash
curl -fsSLO https://scripts.gbdj.cc/ssh-serve.py && bash -c 'python3 ssh-serve.py "$@"' -- -p 2222
```

反向：改用 `-m reverse:user@host:22`。
`-k @路径` 指定公钥。

# Python 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

## 路径：os.path.join 的绝对路径覆盖

```python
os.path.join('/var/data', '/etc/passwd')   # -> '/etc/passwd'
os.path.join('/var/data', '../../etc/passwd')  # -> '/var/data/../../etc/passwd'
```

第一种是最容易漏掉的形态：拼接看着没问题，但用户传绝对路径时基准目录被整个丢弃。`pathlib` 的 `/` 运算符行为相同。

正确写法是 `os.path.realpath` 之后校验前缀（带分隔符）：

```python
full = os.path.realpath(os.path.join(base, name))
if not full.startswith(os.path.realpath(base) + os.sep):
    raise ValueError
```

- Flask 的 `send_from_directory` 内部做了 `safe_join`，相对安全；`send_file` 不做，路径可控即穿越。
- `tarfile.extractall` / `zipfile.extractall` 存在 Zip Slip（tar 还能包含绝对路径与符号链接）。Python 3.12+ 可传 `filter='data'`，旧版本必须自己逐条校验。

## 命令执行

- `shell=True` 时整条字符串交给 shell，元字符全部危险。
- 列表形式且 `shell=False`（默认）不经 shell，风险转移到程序名可控与选项注入（可控值以 `-` 开头）。
- `os.system` / `os.popen` 恒过 shell。
- 需要拼接时用 `shlex.quote`；`shlex.split` 不是转义，别当 sanitizer。

## 反序列化

- `pickle` / `dill` / `marshal` / `jsonpickle` 处理不可信数据即任意代码执行，没有安全用法。
- `yaml.load(data)` 不带安全 Loader 时可实例化任意对象；`yaml.safe_load` 才安全。PyYAML 5.1+ 不带 `Loader` 会告警但仍可能按 `FullLoader` 走，`FullLoader` 历史上也出过绕过。
- `xml`：标准库解析器易受实体膨胀与外部实体影响，用 `defusedxml` 替换。

## SQL

- DB-API 的 `execute(sql, params)` 才是绑定；`execute(sql % params)`、f-string、`.format()` 都是拼接。
- Django ORM 默认安全；风险在 `.raw()`、`.extra()`、`RawSQL`，以及把用户输入直接给 `order_by()` / `values()`（可通过关联字段遍历到不该暴露的数据）。
- SQLAlchemy：`text("... where id = %s" % x)` 是拼接；正确写法是 `text("... where id = :id").bindparams(id=x)`。
- 表名、列名、排序方向仍然只能白名单。

## 模板与求值

- `render_template_string(user_input)`、`jinja2.Template(user_input)` 是 SSTI，Jinja2 可经 `__class__` / `__subclasses__` 链升级到 RCE。
- Flask 的自动转义只对 `.html` / `.htm` / `.xml` / `.xhtml` 后缀的模板默认开启；**手工构造的 `Template()` 默认不转义**。
- `eval` / `exec` / `compile` 无安全用法。`ast.literal_eval` 是安全替代。
- 格式化字符串攻击：`"{}".format(obj)` 里若格式串可控，可通过 `{0.__class__.__init__.__globals__}` 读到全局对象。f-string 是编译期的，不受此影响。

## 框架与部署

- `assert` 做权限校验：`python -O` 下 assert 被移除，校验直接消失。
- Django `DEBUG = True` 在生产会暴露配置与堆栈；`ALLOWED_HOSTS = ['*']` 配合 Host 头可造缓存投毒 / 密码重置链接劫持。
- Flask `app.run(debug=True)` 暴露 Werkzeug 调试器（可直接执行代码）。
- 上传：`file.filename` 完全由客户端控制，`werkzeug.utils.secure_filename` 会剥掉路径成分（但也会改变文件名，注意业务影响）。
- `requests` 默认跟随重定向：SSRF 校验必须 `allow_redirects=False` 或逐跳校验。`verify=False` 关闭证书校验。

## 加密与随机

- `hashlib.md5/sha1` 用于口令或签名不可接受；口令用 `bcrypt` / `argon2` / `hashlib.scrypt`。
- 令牌 / 重置码 / 会话 ID 用 `secrets`，不用 `random`（`random` 是 Mersenne Twister，可由若干输出反推状态）。
- 比较密钥用 `hmac.compare_digest`。

## 其他

- `subprocess` / `open` 之外，`pandas.read_pickle`、`joblib.load`、`torch.load`、`numpy.load(allow_pickle=True)` 都是隐藏的 pickle 入口。
- `input()` 在 Python 2 下等价 eval（老代码才会遇到）。
- 异常处理里 `except Exception: pass` 吞掉安全校验的失败，是链路成立的常见原因。

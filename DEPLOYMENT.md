# 华为设备配置与日志分析工具 - 部署教程

本文档介绍如何将本工具部署为 Web 服务，涵盖本地开发、生产部署（Gunicorn + Nginx）、Docker 容器化三种方式。

---

## 1. 项目结构

```
huawei-analyzer/
├── huawei_analyzer/        # 核心分析库（CLI 与 Web 共用）
│   ├── __init__.py
│   ├── main.py              # CLI 入口（仍可单独使用）
│   ├── detector.py          # 设备类型自动识别
│   ├── checker.py           # 安全合规检查
│   ├── reporter.py          # Text/HTML 报告生成
│   └── parsers/
│       ├── _common.py       # 共享 AAA 解析
│       ├── firewall.py      # 防火墙配置解析
│       ├── switch.py         # 交换机配置解析
│       └── log_parser.py    # 日志解析
├── web/                     # Flask Web 应用
│   ├── app.py               # 后端：上传/分析/报告 API
│   ├── templates/
│   │   └── index.html       # 主界面
│   └── static/
│       ├── app.js           # 前端交互
│       └── style.css        # 样式
├── samples/                 # 示例文件
├── requirements.txt         # Python 依赖
└── DEPLOYMENT.md            # 本文档
```

---

## 2. 环境要求

| 项 | 要求 |
|----|------|
| 操作系统 | Linux / macOS / Windows |
| Python | 3.9 及以上（推荐 3.10+） |
| 依赖 | Flask >= 3.0（已写入 `requirements.txt`） |
| 磁盘 | 至少 100 MB（用于临时存储上传文件与生成的报告） |
| 网络 | Web 服务监听端口（默认 5000），客户端浏览器可访问 |

> 上传的配置/日志文件仅在服务器本地处理，**不会**外发到任何外部服务。

---

## 3. 快速开始（本地开发模式）

适用于开发调试或单人本机使用。

### 3.1 安装依赖

```bash
# 进入项目根目录
cd /path/to/huawei-analyzer

# (推荐) 创建并激活虚拟环境
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows PowerShell

# 安装依赖
pip install -r requirements.txt
```

### 3.2 启动 Web 服务

```bash
python3 web/app.py
```

看到如下输出即代表启动成功：

```
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

### 3.3 访问界面

浏览器打开 `http://127.0.0.1:5000`，操作步骤：

1. **上传文件**：将 `.cfg / .conf / .txt / .log` 文件拖拽到上传区，或点击选择。支持一次选择多个文件。
2. **可选配置**：如分析日志，可在「日志过滤起始/结束时间」填写 `YYYY-MM-DD HH:MM:SS` 进行时间窗过滤。
3. **开始分析**：点击「开始分析」按钮，等待几秒后页面下方显示汇总统计与各设备标签。
4. **查看报告**：点击标签（如「批量汇总」「USG6000V1 (firewall)」）切换查看对应设备的 HTML 报告；可点击「下载 TXT / HTML」保存到本地。

### 3.4 同时保留的 CLI 用法

Web 化后命令行工具仍然可用，适合脚本化批处理：

```bash
# 批量分析目录
python3 -m huawei_analyzer.main -i ./samples -o ./reports -f both

# 单文件 + 日志时间窗
python3 -m huawei_analyzer.main -i device.log \
    --log-start "2024-01-15 10:00:00" --log-end "2024-01-15 23:59:59"
```

---

## 4. 生产部署（Gunicorn + Nginx）

开发服务器（`app.run()`）不适合生产。推荐使用 Gunicorn 作为 WSGI 服务器，配合 Nginx 反向代理。

### 4.1 安装生产依赖

```bash
pip install -r requirements.txt gunicorn
```

### 4.2 使用 Gunicorn 启动

```bash
# 4 worker 进程，监听 127.0.0.1:8000（仅本机，由 Nginx 转发）
# app:app  = 文件 web/app.py 中的 Flask app 对象
gunicorn -w 4 -b 127.0.0.1:8000 "web.app:app"
```

常用参数：

| 参数 | 说明 |
|------|------|
| `-w 4` | worker 进程数，建议 CPU 核数 × 2 + 1 |
| `-b 127.0.0.1:8000` | 监听地址与端口 |
| `--timeout 120` | 请求超时秒数（大文件分析建议调大） |
| `--access-logfile -` | 输出访问日志到 stdout |
| `--error-logfile -` | 输出错误日志到 stdout |

### 4.3 使用 systemd 托管（Linux）

创建 `/etc/systemd/system/huawei-analyzer.service`：

```ini
[Unit]
Description=Huawei Device Analyzer Web Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/huawei-analyzer
Environment="PATH=/path/to/huawei-analyzer/.venv/bin"
ExecStart=/path/to/huawei-analyzer/.venv/bin/gunicorn \
    -w 4 -b 127.0.0.1:8000 --timeout 120 \
    "web.app:app"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable huawei-analyzer
sudo systemctl start huawei-analyzer
sudo systemctl status huawei-analyzer     # 查看运行状态
```

### 4.4 配置 Nginx 反向代理

在 `/etc/nginx/conf.d/huawei-analyzer.conf`（或 `sites-available/` 下）添加：

```nginx
server {
    listen 80;
    server_name analyzer.example.com;   # 替换为你的域名或 IP

    client_max_body_size 32m;            # 与 app.py 中 MAX_CONTENT_LENGTH 一致

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

测试并重载 Nginx：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

访问 `http://analyzer.example.com` 即可使用。

### 4.5 启用 HTTPS（推荐）

使用 Let's Encrypt 签发免费证书：

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d analyzer.example.com
```

证书自动续期已由 certbot 配置好。

---

## 5. Docker 容器化部署

适合快速部署到任意环境，无需在宿主机安装 Python。项目根目录已包含 `Dockerfile` 和 `.dockerignore`。

### 5.1 Dockerfile 说明

项目自带的 `Dockerfile` 内容如下：

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖（利用层缓存）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY huawei_analyzer/ ./huawei_analyzer/
COPY web/ ./web/

# 创建临时作业和报告目录
RUN mkdir -p /app/web_jobs /app/reports

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 5000

# Gunicorn 生产级 WSGI 服务器
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "--timeout", "120", "web.app:app"]
```

### 5.2 构建并运行

```bash
# 进入项目根目录
cd /path/to/huawei-analyzer

# 构建镜像
docker build -t huawei-analyzer:1.0 .

# 运行容器（将宿主机 8080 映射到容器 5000）
docker run -d \
    --name huawei-analyzer \
    -p 8080:5000 \
    --restart unless-stopped \
    huawei-analyzer:1.0
```

访问 `http://localhost:8080`。

### 5.3 查看容器日志

```bash
docker logs -f huawei-analyzer
```

### 5.4 使用 docker-compose（可选）

创建 `docker-compose.yml`：

```yaml
services:
  analyzer:
    build: .
    image: huawei-analyzer:1.0
    container_name: huawei-analyzer
    ports:
      - "8080:5000"
    restart: unless-stopped
```

启动：

```bash
docker compose up -d
docker compose logs -f      # 查看日志
docker compose down          # 停止
```

### 5.5 配合 Nginx 的完整 compose 示例（可选）

```yaml
services:
  analyzer:
    build: .
    restart: unless-stopped
    expose:
      - "5000"

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - analyzer
```

`nginx.conf`：

```nginx
server {
    listen 80;
    client_max_body_size 32m;
    location / {
        proxy_pass http://analyzer:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 120s;
    }
}
```

---

## 6. 配置项

通过环境变量调整行为：

| 环境变量 | 默认值 | 说明 |
|----------|--------|------|
| `PORT` | `5000` | 开发模式 (`python web/app.py`) 监听端口 |
| `HOST` | `127.0.0.1` | 开发模式监听地址（设为 `0.0.0.0` 可外网访问） |
| `HUAWEI_ANALYZER_JOBS_DIR` | `<项目>/web_jobs` | 上传文件与生成报告的存储目录 |

设置示例：

```bash
# 监听所有网卡、端口 8080，自定义 jobs 目录
HOST=0.0.0.0 PORT=8080 \
HUAWEI_ANALYZER_JOBS_DIR=/var/lib/huawei-analyzer/jobs \
python3 web/app.py
```

---

## 7. 安全注意事项

1. **绑定地址**：开发模式下默认绑定 `127.0.0.1`（仅本机）。若需对外服务，请通过 Nginx 暴露并配置访问控制，不要直接将 `app.run(host='0.0.0.0')` 暴露到公网。
2. **上传限制**：单文件上限 32 MB（`app.py` 中 `MAX_CONTENT_LENGTH`），如有更大配置文件可调大，同时同步修改 Nginx 的 `client_max_body_size`。
3. **临时文件清理**：每次请求会自动清理超过 1 小时的旧 job 目录；最多保留 20 个最近 job。如磁盘紧张，可挂载独立卷到 `HUAWEI_ANALYZER_JOBS_DIR`。
4. **认证授权**：本工具默认无登录认证。若部署在内网共享环境，建议在 Nginx 层加 Basic Auth 或限制来源 IP：

   ```nginx
   # 限制来源 IP
   allow 10.0.0.0/8;
   deny  all;
   ```

   ```bash
   # 或启用 Basic Auth
   sudo htpasswd -c /etc/nginx/.htpasswd username
   # nginx.conf 中加：
   #   auth_basic "Restricted";
   #   auth_basic_user_file /etc/nginx/.htpasswd;
   ```
5. **传输加密**：生产环境务必启用 HTTPS（见 4.5）。
6. **数据敏感性**：上传的配置文件可能包含口令哈希、网络拓扑等敏感信息。分析完成后如需彻底清除，可手动删除 `web_jobs/` 目录。

---

## 8. 常见问题

**Q1：上传后提示「无法识别文件类型」？**
A：工具依据华为 VRP 配置特征关键字（`firewall zone`、`security-policy`、`vlan batch`、`stp mode` 等）和 VRP 日志头（`%%01MODULE/SEVERITY/MNEMONIC`）识别。请确认：
- 配置文件是 `display current-configuration` 的完整导出，而非片段。
- 交换机配置若为非纯文本格式（如 Word 复制），请先另存为 `.txt`。
- 日志需保留时间戳前缀（`2024-01-15 10:23:45 ...`）。

**Q2：分析大文件时浏览器超时？**
A：调整 Gunicorn `--timeout` 与 Nginx `proxy_read_timeout` 为更大值（如 300s），并确认 `MAX_CONTENT_LENGTH` 够用。

**Q3：如何持久化保存报告？**
A：Web 模式下报告按 job 临时存储。如需长期归档，建议：
- 使用 CLI 模式 `python -m huawei_analyzer.main -i ./configs -o /var/reports` 直接写入持久目录；
- 或在 Nginx 层对 `/api/report/` 与 `/api/batch/` 增加 `expires` 缓存头并挂载到持久卷。

**Q4：能否扩展支持的设备型号？**
A：当前覆盖华为 USG/NGFW 防火墙与 S/CE 系列交换机的 VRP 配置语法。其他厂商设备需在 `huawei_analyzer/parsers/` 下新增对应解析器并在 `detector.py` 增加识别关键字。

**Q5：日志严重等级如何对应？**
A：遵循华为 VRP 标准 0-7 级：0 Emergency / 1 Alert / 2 Critical / 3 Error / 4 Warning / 5 Notification / 6 Informational / 7 Debug。报告中「严重事件」为等级 ≤ 2 的所有事件加上识别为 `security_alert` 类别的全部事件。

---

## 9. 验证部署

部署完成后，使用项目自带的示例文件验证：

```bash
# 命令行验证（CLI 仍可用）
python3 -m huawei_analyzer.main -i ./samples -o ./reports -v
# 预期输出：
#   [firewall] USG6000V1   score=73  H/M/L=7/2/0  miss=1
#   [switch  ] SW-Core-01  score=78  H/M/L=5/1/0  miss=3
#   [log     ] USG6000V1   events=18 critical=3
```

Web 验证：浏览器访问服务地址 → 上传 `samples/` 下三个文件 → 确认能看到汇总统计卡片、各设备标签、内嵌 HTML 报告。

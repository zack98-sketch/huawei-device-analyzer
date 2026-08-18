# 华为设备配置与日志分析工具 - 部署教程

本文档介绍如何从 GitHub 克隆项目并部署为 Web 服务，涵盖 WSL 环境配置、GitHub 绑定、本地开发、Docker 容器化、生产部署（Gunicorn + Nginx）等方式。

---

## 目录

- [1. 项目结构](#1-项目结构)
- [2. WSL 环境配置（从零开始）](#2-wsl-环境配置从零开始)
- [3. GitHub 绑定与代码推送](#3-github-绑定与代码推送)
- [4. 快速开始（本地开发模式）](#4-快速开始本地开发模式)
- [5. Docker 容器化部署](#5-docker-容器化部署)
- [6. 生产部署（Gunicorn + Nginx）](#6-生产部署gunicorn--nginx)
- [7. 配置项](#7-配置项)
- [8. 安全注意事项](#8-安全注意事项)
- [9. 常见问题](#9-常见问题)
- [10. 验证部署](#10-验证部署)

---

## 1. 项目结构

```
huawei-device-analyzer/
├── huawei_analyzer/            # 核心分析库（CLI 与 Web 共用）
│   ├── __init__.py
│   ├── main.py                  # CLI 入口（可单独使用）
│   ├── detector.py              # 设备类型自动识别
│   ├── checker.py               # 安全合规检查
│   ├── reporter.py              # Text/HTML 报告生成
│   ├── traffic_analyzer.py      # 流量日志安全分析
│   └── parsers/
│       ├── _common.py           # 共享 AAA 解析
│       ├── firewall.py           # 防火墙配置解析
│       ├── switch.py             # 交换机配置解析
│       ├── log_parser.py         # 日志解析（VRP/CSV/TSV）
│       └── traffic_log.py        # 流量会话表解析
├── web/                         # Flask Web 应用
│   ├── app.py                   # 后端：上传/分析/报告 API
│   ├── templates/
│   │   └── index.html           # 主界面
│   └── static/
│       ├── app.js               # 前端交互
│       └── style.css            # 样式
├── samples/                     # 示例文件（含 .cfg/.log/.csv）
├── Dockerfile                   # Docker 容器化
├── .dockerignore
├── requirements.txt             # Python 依赖
├── DEPLOYMENT.md                # 本文档
└── README.md
```

---

## 2. WSL 环境配置（从零开始）

适用于 Windows 用户，在 WSL Ubuntu 中从零搭建开发环境。

### 2.1 安装 WSL

如果尚未安装 WSL，在 **PowerShell（管理员）** 中执行：

```powershell
wsl --install -d Ubuntu
```

安装完成后重启，首次启动时设置 Linux 用户名和密码。

如果已有 WSL 但版本较旧，升级到 WSL 2：

```powershell
wsl --set-default-version 2
wsl --update
```

### 2.2 进入 WSL Ubuntu

在 Windows 终端输入：

```bash
wsl
```

或在开始菜单中打开「Ubuntu」。

### 2.3 更新系统包

```bash
sudo apt update && sudo apt upgrade -y
```

### 2.4 安装基础工具

```bash
# Python 3 + pip + venv
sudo apt install -y python3 python3-pip python3-venv

# Git
sudo apt install -y git

# 其他实用工具（可选）
sudo apt install -y curl wget build-essential
```

### 2.5 验证安装

```bash
python3 --version    # 应输出 Python 3.10+
pip3 --version
git --version
```

### 2.6 配置 Git 用户信息

```bash
git config --global user.name "你的GitHub用户名"
git config --global user.email "你的GitHub邮箱"
```

### 2.7（可选）安装 Docker

如果计划使用 Docker 部署，在 WSL 中安装 Docker：

```bash
# 添加 Docker 官方 GPG key 和仓库
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 安装 Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 将当前用户加入 docker 组（免 sudo）
sudo usermod -aG docker $USER

# 刷新组权限（或重新启动 WSL）
newgrp docker

# 验证
docker --version
docker run hello-world
```

> 如果使用 Docker Desktop for Windows，在 Settings → Resources → WSL Integration 中启用你的 WSL 发行版即可，无需在 WSL 内单独安装。

---

## 3. GitHub 绑定与代码推送

### 3.1 方式一：SSH Key（推荐）

#### 3.1.1 生成 SSH 密钥

```bash
ssh-keygen -t ed25519 -C "你的GitHub邮箱"
# 一路回车即可（默认路径 ~/.ssh/id_ed25519，不设密码）
```

#### 3.1.2 查看并复制公钥

```bash
cat ~/.ssh/id_ed25519.pub
```

复制输出的 `ssh-ed25519 AAAA...` 全部内容。

#### 3.1.3 添加到 GitHub

1. 浏览器打开 https://github.com/settings/keys
2. 点击 **New SSH key**
3. Title 填 `WSL-Ubuntu`（或任意名称）
4. Key 粘贴刚才复制的内容
5. 点击 **Add SSH key**

#### 3.1.4 测试连接

```bash
ssh -T git@github.com
# 首次连接提示 "Are you sure you want to continue connecting?"，输入 yes
# 预期输出：Hi <用户名>! You've successfully authenticated...
```

#### 3.1.5 克隆仓库

```bash
cd ~
git clone git@github.com:zack98-sketch/huawei-device-analyzer.git
cd huawei-device-analyzer
```

---

### 3.2 方式二：HTTPS + Token

#### 3.2.1 创建 Personal Access Token

1. 打开 https://github.com/settings/tokens?type=beta （Fine-grained tokens）
2. 点击 **Generate new token**
3. 设置：
   - **Token name**: `wsl-deploy`
   - **Expiration**: 30 天或更长
   - **Repository access**: All repositories 或指定 `huawei-device-analyzer`
   - **Permissions** → Repository permissions → **Contents**: Read and write
4. 生成后复制 `github_pat_...` 字符串（**仅显示一次**）

#### 3.2.2 克隆仓库（使用 Token）

```bash
cd ~
git clone https://github.com/zack98-sketch/huawei-device-analyzer.git
# 提示输入用户名和密码时：
#   Username: zack98-sketch
#   Password: 粘贴刚才创建的 Token（不是 GitHub 密码）
cd huawei-device-analyzer
```

#### 3.2.3 缓存凭据（避免重复输入）

```bash
# 缓存 1 小时
git config --global credential.helper cache
git config --global credential.helper 'cache --timeout=3600'

# 或永久存储（明文保存在 ~/.git-credentials，仅本机使用）
git config --global credential.helper store
```

---

### 3.3 方式三：共享 Windows 凭据

如果已在 Windows 上安装 Git for Windows 并配置过 GitHub 凭据：

```bash
git config --global credential.helper "/mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe"
```

之后在 WSL 中的 `git clone/push/pull` 会复用 Windows 已保存的 GitHub 凭据。

---

### 3.4 推送代码变更

如果你在本地修改了代码，需要推送到 GitHub：

```bash
cd ~/huawei-device-analyzer

# 1. 查看变更
git status
git diff

# 2. 暂存变更
git add .

# 3. 提交
git commit -m "描述你的修改内容"

# 4. 推送到 main 分支
git push origin main
```

---

## 4. 快速开始（本地开发模式）

适用于开发调试或单人本机使用。

### 4.1 安装依赖

```bash
cd ~/huawei-device-analyzer

# 创建并激活虚拟环境
python3 -m venv .venv
source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 4.2 启动 Web 服务

```bash
python3 web/app.py
```

看到如下输出即代表启动成功：

```
 * Serving Flask app 'app'
 * Running on http://127.0.0.1:5000
```

### 4.3 访问界面

浏览器打开 `http://127.0.0.1:5000`，操作步骤：

1. **上传文件**：将 `.cfg / .conf / .txt / .log / .csv` 文件拖拽到上传区，或点击选择。支持一次选择多个文件。
2. **可选配置**：如分析日志，可在「日志过滤起始/结束时间」填写 `YYYY-MM-DD HH:MM:SS` 进行时间窗过滤。
3. **开始分析**：点击「开始分析」按钮，等待几秒后页面下方显示汇总统计与各设备标签。
4. **查看报告**：点击标签切换查看对应设备的 HTML 报告；可点击「下载 TXT / HTML」保存到本地。

### 4.4 CLI 命令行用法

Web 化后命令行工具仍然可用，适合脚本化批处理：

```bash
# 批量分析目录下所有文件
python3 -m huawei_analyzer.main -i ./samples -o ./reports -f both -v

# 单文件 + 日志时间窗过滤
python3 -m huawei_analyzer.main -i device.log \
    --log-start "2024-01-15 10:00:00" --log-end "2024-01-15 23:59:59"

# 单文件输出为 HTML
python3 -m huawei_analyzer.main -i firewall.cfg -o ./reports -f html
```

### 4.5 支持的文件类型

| 类型 | 扩展名 | 自动识别依据 |
|------|--------|-------------|
| 防火墙配置 | `.cfg` `.conf` `.txt` | `firewall zone`、`security-policy`、`nat-policy` 等关键字 |
| 交换机配置 | `.cfg` `.conf` `.txt` | `vlan batch`、`port link-type`、`stp mode` 等关键字 |
| VRP 日志 | `.log` `.txt` | `%%01MODULE/SEVERITY/MNEMONIC` 格式行 |
| CSV 日志 | `.csv` | 逗号分隔，表头含 date/time/module/severity 等 |
| TSV 日志 | `.csv` `.txt` | Tab 分隔，表头含 时间/管理员/内容 等 |
| 流量会话表 | `.csv` | 逗号/Tab 分隔，表头含 src-ip/dst-ip/protocol 等 |

---

## 5. Docker 容器化部署

适合快速部署到任意环境，无需在宿主机安装 Python。

### 5.1 构建并运行

```bash
cd ~/huawei-device-analyzer

# 构建镜像
docker build -t huawei-analyzer:1.0 .

# 运行容器
docker run -d \
    --name huawei-analyzer \
    -p 8080:5000 \
    --restart unless-stopped \
    huawei-analyzer:1.0
```

访问 `http://localhost:8080`。

### 5.2 查看容器日志

```bash
docker logs -f huawei-analyzer
```

### 5.3 使用 docker-compose（可选）

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

### 5.4 配合 Nginx 的完整 compose 示例（可选）

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

### 5.5 容器管理

```bash
# 停止 / 重启 / 删除
docker stop huawei-analyzer
docker restart huawei-analyzer
docker rm -f huawei-analyzer

# 重新构建（代码更新后）
docker build -t huawei-analyzer:1.0 .
docker rm -f huawei-analyzer
docker run -d --name huawei-analyzer -p 8080:5000 --restart unless-stopped huawei-analyzer:1.0
```

---

## 6. 生产部署（Gunicorn + Nginx）

开发服务器（`app.run()`）不适合生产。推荐使用 Gunicorn 作为 WSGI 服务器，配合 Nginx 反向代理。

### 6.1 安装生产依赖

```bash
cd ~/huawei-device-analyzer
source .venv/bin/activate
pip install -r requirements.txt gunicorn
```

### 6.2 使用 Gunicorn 启动

```bash
# 4 worker 进程，监听 127.0.0.1:8000（仅本机，由 Nginx 转发）
gunicorn -w 4 -b 127.0.0.1:8000 --timeout 120 "web.app:app"
```

常用参数：

| 参数 | 说明 |
|------|------|
| `-w 4` | worker 进程数，建议 CPU 核数 × 2 + 1 |
| `-b 127.0.0.1:8000` | 监听地址与端口 |
| `--timeout 120` | 请求超时秒数（大文件分析建议调大） |
| `--access-logfile -` | 输出访问日志到 stdout |
| `--error-logfile -` | 输出错误日志到 stdout |

### 6.3 使用 systemd 托管（Linux）

创建 `/etc/systemd/system/huawei-analyzer.service`：

```ini
[Unit]
Description=Huawei Device Analyzer Web Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/home/<用户名>/huawei-device-analyzer
Environment="PATH=/home/<用户名>/huawei-device-analyzer/.venv/bin"
ExecStart=/home/<用户名>/huawei-device-analyzer/.venv/bin/gunicorn \
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

### 6.4 配置 Nginx 反向代理

在 `/etc/nginx/conf.d/huawei-analyzer.conf` 添加：

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

### 6.5 启用 HTTPS（推荐）

使用 Let's Encrypt 签发免费证书：

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d analyzer.example.com
```

证书自动续期已由 certbot 配置好。

---

## 7. 配置项

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

## 8. 安全注意事项

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

5. **传输加密**：生产环境务必启用 HTTPS（见 6.5）。
6. **数据敏感性**：上传的配置文件可能包含口令哈希、网络拓扑等敏感信息。分析完成后如需彻底清除，可手动删除 `web_jobs/` 目录。

---

## 9. 常见问题

**Q1：上传后提示「无法识别文件类型」？**

A：工具依据华为 VRP 配置特征关键字和日志格式自动识别。请确认：
- 配置文件是 `display current-configuration` 的完整导出，而非片段。
- 交换机配置若为非纯文本格式（如 Word 复制），请先另存为 `.txt`。
- 日志需保留时间戳前缀（`2024-01-15 10:23:45 ...`）。
- CSV/TSV 日志需包含表头行（`date,time,module,severity,...` 或 `时间,管理员,...`）。

**Q2：分析大文件时浏览器超时？**

A：调整 Gunicorn `--timeout` 与 Nginx `proxy_read_timeout` 为更大值（如 300s），并确认 `MAX_CONTENT_LENGTH` 够用。

**Q3：如何持久化保存报告？**

A：Web 模式下报告按 job 临时存储。如需长期归档，建议：
- 使用 CLI 模式 `python -m huawei_analyzer.main -i ./configs -o /var/reports` 直接写入持久目录；
- 或在 Nginx 层对 `/api/report/` 与 `/api/batch/` 增加 `expires` 缓存头并挂载到持久卷。

**Q4：Docker 容器启动后无法访问？**

A：检查：
- 容器是否正常运行：`docker ps`
- 端口映射是否正确：`docker port huawei-analyzer`
- 防火墙是否放行 8080：`sudo ufw allow 8080`
- 查看容器日志：`docker logs huawei-analyzer`

**Q5：WSL 中 Docker 命令提示 permission denied？**

A：当前用户未加入 docker 组，执行：
```bash
sudo usermod -aG docker $USER
newgrp docker
```
如果仍不生效，关闭 WSL 后重新打开（`wsl --shutdown` → 重新启动）。

**Q6：git push 提示 Authentication failed？**

A：Token 已过期或权限不足。重新创建 Token（见 3.2.1），然后：
```bash
# 清除旧凭据
git config --global --unset credential.helper
git config --global credential.helper store
# 再次 push 时输入新 Token
git push origin main
```

**Q7：日志严重等级如何对应？**

A：遵循华为 VRP 标准 0-7 级：0 Emergency / 1 Alert / 2 Critical / 3 Error / 4 Warning / 5 Notification / 6 Informational / 7 Debug。报告中「严重事件」为等级 ≤ 2 的所有事件加上识别为 `security_alert` 类别的全部事件。

---

## 10. 验证部署

部署完成后，使用项目自带的示例文件验证：

### CLI 验证

```bash
cd ~/huawei-device-analyzer
source .venv/bin/activate   # 如果使用虚拟环境

python3 -m huawei_analyzer.main -i ./samples -o ./reports -v
```

预期输出类似：

```
[firewall  ] USG6000V1       score=57   H/M/L=10/5/1  miss=1
[switch    ] SW-Core-01      score=81   H/M/L=4/1/0   miss=3
[log       ] USG6000V1       events=18 critical=3
[log       ] CORE-SW-01      events=6  critical=1
[log       ] public          events=17 critical=1
[traffic   ] traffic_sample  sessions=26 out=6 in=0
[log       ] USG6000-FW      events=12 critical=3
```

### Web 验证

浏览器访问服务地址 → 上传 `samples/` 下的文件 → 确认能看到：
- 汇总统计卡片（设备数、文件数、风险分布）
- 各设备标签（防火墙、交换机、日志、流量）
- 内嵌 HTML 报告
- 下载 TXT / HTML 报告按钮

### Docker 验证

```bash
docker logs huawei-analyzer
# 预期看到：
# [INFO] Starting gunicorn 21.x.x
# [INFO] Listening at: http://0.0.0.0:5000
# [INFO] Booting worker with pid: ...

curl -s http://localhost:8080/ | head -5
# 预期返回 HTML 页面内容
```

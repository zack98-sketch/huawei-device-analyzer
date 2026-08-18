FROM python:3.12-slim

LABEL maintainer="huawei-analyzer"

# 设置工作目录
WORKDIR /app

# 安装系统依赖（编译 gevent 等可选 C 扩展时可能需要）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 先复制依赖文件，利用 Docker 缓存层
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# 复制应用代码
COPY huawei_analyzer/ ./huawei_analyzer/
COPY web/ ./web/

# 创建临时作业和报告目录
RUN mkdir -p /app/web_jobs /app/reports

# 设置环境变量
ENV FLASK_APP=web.app
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# 暴露端口
EXPOSE 5000

# 使用 Gunicorn 运行（生产级 WSGI 服务器）
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "--timeout", "120", "web.app:app"]

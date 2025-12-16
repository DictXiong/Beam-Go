# Beam-Go (Bingo\!) ⚡️

> 本项目使用了 AI 辅助编码

**Beam-Go** 是一个专注于**现有文件系统的、轻量级**私密文件分享服务。

名字来源于 **"Beam"** (光束/传送) 和 **"Go"** 的组合，读起来像 **"Bingo\!"** —— 寓意当你需要从服务器上快速分享一个现存文件给朋友时，它能让你瞬间搞定。

欢迎任何 Issue 和 PR！

## 💡 为什么开发 Beam-Go？

Beam-Go 的诞生源于我在管理服务器时的一个特定痛点：**我需要将服务器上现有的某个文件或目录，通过私密链接分享给外部用户。**

在开发 Beam-Go 之前，我考察了市面上主流的方案，但都不完美：

| 方案 | 是否支持现有文件 | 安全性/隐私 | 重量级 | 缺点分析 |
| :--- | :--- | :--- | :--- | :--- |
| **Nginx Autoindex** | ✅ 支持 | ❌ 低 | 🟢 轻 | 直接暴露整个目录结构，毫无隐私可言；若想只分享特定文件，需要维护大量复杂的软链接。 |
| **Nextcloud** | ✅ 支持 (External Storage) | ✅ 高 | 🔴 重 | 功能过于庞大，环境依赖重（PHP/Database），仅为了分享文件属于“杀鸡用牛刀”。 |
| **Seafile** | ❌ 不支持 | ✅ 高 | 🟡 中 | 必须将文件上传/导入到其私有存储块中，无法直接读取服务器上的现有文件系统。 |
| **Beam-Go** | **✅ 原生支持** | **✅ 中 (Token验证)** | **🟢 极轻** | **直接映射本地路径，通过随机 Token 访问，无数据搬运，单一二进制文件。** |

**Beam-Go 的核心哲学是：** 不侵入文件系统，不搬运数据，用完即走，通过随机 Token 实现低成本的访问控制。

## ✨ 功能特性

  * **⚡️ 原位分享 (In-place Sharing)**: 无需上传，无需移动，直接分享服务器上的绝对路径。
  * **🔐 访问控制**: 基于随机 6 位字符代码（Code）生成私密链接，如同隐式密码，防止暴力扫描。
  * **📦 目录浏览与打包**: 分享目录时，支持网页端浏览文件列表，或一键流式打包下载 (ZIP)。
  * **⏱ 自动过期**: 支持自定义有效期（默认 7 天），过期链接自动失效。
  * **🛡 公网友好**: 专为长期运行设计，配合 Nginx 反向代理可安全暴露于公网。
  * **🚀 极简部署**: 客户端与服务端合二为一，无环境依赖。

## 🛠 安装与编译

你需要安装 [Go](https://go.dev/) 环境（建议 Go 1.18+）。

```bash
git clone https://github.com/DictXiong/Beam-Go.git
cd Beam-Go
go build -o beam main.go

# 建议移动到系统路径
sudo mv beam /usr/local/bin/
```

## 📖 运行指南

Beam-Go 采用 C/S 架构：后台服务 (`serve`) 负责处理 HTTP 请求，命令行工具 (`add/del`) 用于管理分享。

### 1\. 启动服务 (服务端)

为了长期稳定运行，建议使用 Systemd 管理（见下文部署章节）。临时测试可直接运行：

```bash
# 启动服务，默认监听 8280 端口，必须指定数据库目录
beam serve -d /var/lib/beam-go
```

### 2\. 分享现有文件 (客户端)

在服务器的任意路径下，直接将本地文件映射到公网。

```bash
# 分享当前目录下的视频文件，有效期 3 天（默认为 7 天）
beam add -d 3 /mnt/media/movies/holiday.mp4

# 分享整个日志目录
beam add /var/log/nginx
```

**输出示例：**

```text
✅ 分享成功
Code:   xK9m2P
Path:   /mnt/media/movies/holiday.mp4
Type:   文件
Expire: 2025-12-20T14:00:00+08:00
```

此时，外部用户通过访问 `http://your-server.com/s/xK9m2P` 即可下载该视频，且无法访问服务器上的其他文件。

### 3\. 管理分享

```bash
# 列出当前所有活跃的分享
beam list

# 删除指定分享（使链接立即失效）
beam del /mnt/media/movies/holiday.mp4
```

## ⚙️ 生产环境部署 (Public Facing)

为了将 Beam-Go 安全地暴露给公网，强烈建议使用 **Systemd** 进行进程守护，并使用 **Nginx** 配置 SSL 和反向代理。

### 1\. Systemd 配置 (长期运行)

创建服务文件 `/etc/systemd/system/beam.service`:

```ini
[Unit]
Description=Beam-Go File Sharing Service
After=network.target

[Service]
Type=simple
User=root
# 建议指定一个持久化的数据目录
ExecStart=/usr/local/bin/beam serve -d /var/lib/beam-go -p :8280 -s /var/run/beam-go.sock
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo mkdir -p /var/lib/beam-go
sudo systemctl enable --now beam
```

### 2\. Nginx 反向代理 (推荐)

不建议直接将 Beam-Go 暴露在公网，建议通过 Nginx 转发，并配置 HTTPS。

```nginx
server {
    listen 80;
    server_name share.your-domain.com;

    # 推荐使用 Let's Encrypt 获取 SSL 证书
    # listen 443 ssl; ...

    location / {
        proxy_pass http://127.0.0.1:8280;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # 针对大文件下载的优化
        proxy_buffering off;
    }
}
```

## 🔒 安全设计与提示

  * **隐式密码 (Token)**: Beam-Go 通过随机 6 位字符（区分大小写）作为 URL 的一部分。只有拥有完整链接的人才能访问。
  * **权限隔离**: Beam-Go 会校验软链接，禁止访问分享路径之外的文件（防止 Path Traversal 攻击）。
  * **Rate Limit**: 内置基础的 IP 访问频率限制，防止暴力穷举 Token。

## 📄 License

MIT License
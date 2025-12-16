# Beam-Go (Bingo\!) ⚡️

> This project was developed with AI-assisted coding

**Beam-Go** is a **lightweight** private file sharing service focused on sharing **existing files** directly from your file system.

The name comes from combining **"Beam"** (teleport/transmit) and **"Go"**. It sounds like **"Bingo\!"**—signifying that moment when you need to instantly share a file from your server to a friend, and it just works.

Issues and PRs are welcomed!

## 💡 Why Beam-Go?

Beam-Go was born out of a specific pain point I faced while managing my server: **I needed to share an *existing* file or directory on the server via a private link to external users.**

Before building Beam-Go, I evaluated the mainstream solutions, but none were perfect for this specific use case:

| Solution | Supports Existing Files | Security/Privacy | Weight | Drawbacks |
| :--- | :--- | :--- | :--- | :--- |
| **Nginx Autoindex** | ✅ Yes | ❌ Low | 🟢 Light | Exposes the entire directory structure with zero privacy; sharing specific files requires maintaining messy symlinks. |
| **Nextcloud** | ✅ Yes (External Storage) | ✅ High | 🔴 Heavy | Huge codebase and heavy dependencies (PHP/DB); complete overkill just for sharing a few files. |
| **Seafile** | ❌ No | ✅ High | 🟡 Medium | Requires uploading/importing files into its own private storage blocks; cannot read the server's existing file system directly. |
| **Beam-Go** | **✅ Native Support** | **✅ Medium (Token)** | **🟢 Very Light** | **Directly maps local paths, access via random tokens, no data migration, single binary.** |

**The Philosophy of Beam-Go:** Do not intrude on the file system, do not move data, use it and leave it, and enforce access control via random tokens.

## ✨ Features

  * **⚡️ In-place Sharing**: No uploading, no moving files. Share absolute paths directly from your server.
  * **🔐 Access Control**: Private links are generated with a random 6-character alphanumeric code (Token). This acts as an implicit password to prevent brute-force scanning.
  * **📦 Directory Browsing & Packing**: When sharing directories, users can browse files via a Web UI or stream the entire folder as a **ZIP download** with one click.
  * **⏱ Auto-Expiration**: Custom expiration time (default 7 days). Links automatically self-destruct after expiration.
  * **🛡 Public-Facing Ready**: Designed for long-running services; works perfectly behind Nginx reverse proxies.
  * **🚀 Simple Deployment**: The client and server are bundled in a single binary with zero dependencies.

## 🛠 Installation

You need [Go](https://go.dev/) installed (Go 1.18+ recommended).

```bash
git clone https://github.com/DictXiong/Beam-Go.git
cd Beam-Go
go build -o beam main.go

# Recommended: move to system path
sudo mv beam /usr/local/bin/
```

## 📖 Usage Guide

Beam-Go uses a C/S architecture: the background service (`serve`) handles HTTP requests, and the CLI tools (`add`/`del`) manage shares.

### 1\. Start Service (Server)

For long-term stability, it is recommended to use Systemd (see Deployment section). For temporary testing:

```bash
# Start service, listen on port 8280, specify DB directory
beam serve -d /var/lib/beam-go
```

### 2\. Share Existing Files (Client)

You can map any local file on your server to the public web instantly.

```bash
# Share a video file in the current directory, valid for 3 days (default to 7 days)
beam add -d 3 /mnt/media/movies/holiday.mp4

# Share a system log directory
beam add /var/log/nginx
```

**Output Example:**

```text
✅ Share Success
Code:   xK9m2P
Path:   /mnt/media/movies/holiday.mp4
Type:   File
Expire: 2025-12-20T14:00:00+08:00
```

External users can now download the video by visiting `http://your-server.com/s/xK9m2P`. Access to other files on the server is strictly forbidden.

### 3\. Manage Shares

```bash
# List all active shares
beam list

# Delete a specific share (invalidate the link immediately)
beam del /mnt/media/movies/holiday.mp4
```

## ⚙️ Production Deployment

To safely expose Beam-Go to the public internet, it is highly recommended to use **Systemd** for process management and **Nginx** for SSL/Reverse Proxy.

### 1\. Systemd Configuration

Create a service file at `/etc/systemd/system/beam.service`:

```ini
[Unit]
Description=Beam-Go File Sharing Service
After=network.target

[Service]
Type=simple
User=root
# Ensure the DB directory is persistent
ExecStart=/usr/local/bin/beam serve -d /var/lib/beam-go -p :8280 -s /var/run/beam-go.sock
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo mkdir -p /var/lib/beam-go
sudo systemctl enable --now beam
```

### 2\. Nginx Reverse Proxy (Recommended)

Do not expose Beam-Go directly. Use Nginx to handle HTTPS and headers.

```nginx
server {
    listen 80;
    server_name share.your-domain.com;

    # Recommended: Use Let's Encrypt for SSL
    # listen 443 ssl; ...

    location / {
        proxy_pass http://127.0.0.1:8280;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Optimization for large file downloads
        proxy_buffering off;
    }
}
```

## 🔒 Security Design

  * **Implicit Password (Token)**: Beam-Go relies on a 6-character random code (case-sensitive) as part of the URL. Only those with the full link can access the file.
  * **Permission Isolation**: The system strictly validates symlinks and paths to prevent Path Traversal attacks, ensuring users cannot access files outside the shared path.
  * **Rate Limiting**: Built-in IP-based rate limiting prevents brute-force attacks against the tokens.

## 📄 License

MIT License

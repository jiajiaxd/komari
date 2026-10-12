# Quick Start

Komari can be deployed with the management script or with Docker. Both options create the server panel first; after that, add agents from the admin dashboard.

## Option 1: Management Script

Use this on systemd-based Linux distributions such as Ubuntu and Debian.

```bash
curl -fsSL https://raw.githubusercontent.com/jiajiaxd/komari/main/install-komari.sh -o install-komari.sh
chmod +x install-komari.sh
sudo ./install-komari.sh
```

Follow the prompts in the terminal. The script installs Komari and sets it up as a system service.

## Option 2: Docker

```bash
mkdir -p ./data
docker run -d \
  -p 25774:25774 \
  -v $(pwd)/data:/app/data \
  --name komari \
  --restart unless-stopped \
  ghcr.io/jiajiaxd/komari:latest
```

Open `http://<your-server-ip>:25774` in your browser. On first access, use the installation guide to create the administrator account and site settings.

## Next Steps

- [Docker deployment](https://github.com/jiajiaxd/komari/blob/main/docs/en/install/docker.md)
- [Binary deployment](https://github.com/jiajiaxd/komari/blob/main/docs/en/install/binary.md)
- [Build from source](https://github.com/jiajiaxd/komari/blob/main/docs/en/install/compile.md)
- [1Panel deployment](https://github.com/jiajiaxd/komari/blob/main/docs/en/install/1panel.md)
- [Update guide](https://github.com/jiajiaxd/komari/blob/main/docs/en/install/update.md)
- [Agent auto discovery](https://github.com/jiajiaxd/komari/blob/main/docs/en/install/agent-ad.md)

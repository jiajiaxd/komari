# 快速安装

我们提供了一键脚本和 Docker 镜像，方便您快速部署 Komari。

## 方式1：使用一键管理脚本

适用于使用了 `systemd` 的发行版（Ubuntu、Debian...）。

```bash
curl -fsSL https://raw.githubusercontent.com/jiajiaxd/komari/main/install-komari.sh -o install-komari.sh
chmod +x install-komari.sh
sudo ./install-komari.sh
```

## 方式2：使用 Docker

```bash
mkdir -p ./data
docker run -d \
  -p 25774:25774 \
  -v $(pwd)/data:/app/data \
  --name komari \
  --restart unless-stopped \
  ghcr.io/jiajiaxd/komari:latest
docker logs komari
```

访问 `http://<your-ip>:25774` 即可看到 Komari 的仪表盘。

## 其他安装方式

如果您需要更详细的安装指南，请参考：

- [Docker 部署](https://github.com/jiajiaxd/komari/blob/main/docs/install/docker.md)
- [二进制安装](https://github.com/jiajiaxd/komari/blob/main/docs/install/binary.md)
- [手动编译](https://github.com/jiajiaxd/komari/blob/main/docs/install/compile.md)
- [1Panel 部署](https://github.com/jiajiaxd/komari/blob/main/docs/install/1panel.md)
- [更新](https://github.com/jiajiaxd/komari/blob/main/docs/install/update.md)

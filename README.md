# lumine

A lightweight local SOCKS5 server written in Golang that protects HTTPS connections. Forked from [moi-si/lumine](https://github.com/moi-si/lumine)

## Installation

```
go install github.com/zzjc1234/lumine@latest
```

## Usage

```
lumine [-config /path/to/config.json] -addr 127.0.0.1:1080

curl --socks5-hostname 127.0.0.1:1080 https://github.com
```

## Local DNS over UDP

See [YukiDNS](https://github.com/moi-si/yukidns).

## License

GPL-3.0

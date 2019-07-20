# v2ray-http-header-bypass
利用 v2ray 的 tcp 头部伪装实现将伪装流量与正常 http 流量分流，程序将`method`为`V2RAY`的请求发给目标服务器 (v2ray)，为其他的请求发给绕行服务器(caddy 等 web 服务器)。
# example 
`v2ray-http-header-bypass -l :443 -d 127.0.0.1:8000 -b 127.0.0.1:8080 -cert /path/to/tls/cert -key /path/to/tls/key`
inbound (server side)
```json
{
    "port": 8000,
    "protocol": "vmess",
    "settings": {
        "clients": [
            {
                "id": "b831381d-6324-4d53-ad4f-8cda48b30811"
            }
        ]
    },
    "streamSettings": {
        "network": "tcp",
        "tcpSettings": {
            "header": {
                "type": "http"
            }
        }
    }
}
```
outbound (client side)
```json
{
    "protocol": "vmess",
    "settings": {
        "vnext": [
            {
                "address": "example.com",
                "port": 443,
                "users": [
                    {
                        "id": "b831381d-6324-4d53-ad4f-8cda48b30811"
                    }
                ]
            }
        ]
    },
    "streamSettings": {
        "security": "tls",
        "network": "tcp",
        "tcpSettings": {
            "header": {
                "type": "http",
                "request": {
                    "method": "V2RAY"
                }
            }
        }
    }
}
```
Web 服务器监听 http://127.0.0.1:8080

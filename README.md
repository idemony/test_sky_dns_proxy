# SkyDNS DNS proxy

DNS-прокси на Python, который слушает `127.0.0.1:5353`, добавляет в запрос EDNS0-опцию `65520` с 4-байтовым токеном фильтрации, пересылает запрос на `193.58.251.251:53`, логирует категории из EDNS0-опции `65000` и возвращает клиенту DNS-ответ без изменений.

## Установка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
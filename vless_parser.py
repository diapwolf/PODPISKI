#!/usr/bin/env python3
"""
Парсер vless URL и обновление конфигурации
"""

import json
import re
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional

def parse_vless_url(vless_url: str) -> Optional[Dict]:
    """
    Парсит vless URL и возвращает словарь с параметрами
    """
    try:
        # Убираем комментарий если есть
        if '#' in vless_url:
            vless_url = vless_url.split('#')[0]
        
        # Парсим URL
        parsed = urlparse(vless_url)
        
        if parsed.scheme != 'vless':
            return None
        
        # Извлекаем UUID
        uuid = parsed.username
        
        # Извлекаем адрес и порт
        hostname = parsed.hostname
        port = parsed.port or 443
        
        # Парсим параметры запроса
        params = parse_qs(parsed.query)
        
        # Извлекаем основные параметры
        security = params.get('security', ['tls'])[0]
        encryption = params.get('encryption', ['none'])[0]
        flow = params.get('flow', [''])[0]
        type_param = params.get('type', ['tcp'])[0]
        fp = params.get('fp', [''])[0]
        pbk = params.get('pbk', [''])[0]
        sni = params.get('sni', [''])[0]
        sid = params.get('sid', [''])[0]
        
        return {
            'uuid': uuid,
            'address': hostname,
            'port': port,
            'security': security,
            'encryption': encryption,
            'flow': flow,
            'type': type_param,
            'fp': fp,
            'pbk': pbk,
            'sni': sni,
            'sid': sid
        }
    except Exception as e:
        print(f"Ошибка парсинга URL {vless_url}: {e}")
        return None

def create_vless_outbound(vless_config: Dict, tag: str) -> Dict:
    """
    Создает outbound конфигурацию для vless
    """
    if vless_config['security'] == 'reality':
        # Reality настройки
        outbound = {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": vless_config['address'],
                    "port": vless_config['port'],
                    "users": [{
                        "id": vless_config['uuid'],
                        "flow": vless_config['flow']
                    }]
                }]
            },
            "streamSettings": {
                "network": vless_config['type'],
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"{vless_config['sni']}:443" if vless_config['sni'] else "www.microsoft.com:443",
                    "xver": 0,
                    "serverName": vless_config['sni'] if vless_config['sni'] else "www.microsoft.com",
                    "publicKey": vless_config['pbk'],
                    "shortId": vless_config['sid'] if vless_config['sid'] else "",
                    "spiderX": "/"
                }
            }
        }
    else:
        # Обычные TLS настройки
        outbound = {
            "tag": tag,
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": vless_config['address'],
                    "port": vless_config['port'],
                    "users": [{
                        "id": vless_config['uuid'],
                        "flow": vless_config['flow']
                    }]
                }]
            },
            "streamSettings": {
                "network": vless_config['type'],
                "security": vless_config['security'],
                "tlsSettings": {
                    "serverName": vless_config['sni'] if vless_config['sni'] else vless_config['address'],
                    "allowInsecure": False
                }
            }
        }
    
    return outbound

def update_vless_config(config_path: str, vless_urls: List[str]):
    """
    Обновляет конфигурацию vless клиента с новыми URL
    """
    try:
        # Загружаем текущую конфигурацию
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Создаем новые outbounds
        new_outbounds = []
        
        for i, url in enumerate(vless_urls):
            vless_config = parse_vless_url(url)
            if vless_config:
                tag = f"vless-{i+1}"
                outbound = create_vless_outbound(vless_config, tag)
                new_outbounds.append(outbound)
                print(f"✅ Добавлен ключ {i+1}: {vless_config['address']}:{vless_config['port']}")
        
        # Если нет активных ключей, отключаем все
        if not vless_urls:
            new_outbounds = [{
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            }]
            print("❌ Все vless ключи отключены")
        else:
            # Добавляем direct outbound в конец
            new_outbounds.append({
                "tag": "direct",
                "protocol": "freedom",
                "settings": {}
            })
            print(f"✅ Обновлено {len(vless_urls)} vless ключей")
        
        # Обновляем конфигурацию
        config["outbounds"] = new_outbounds
        
        # Сохраняем конфигурацию
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Конфигурация сохранена в {config_path}")
        
    except Exception as e:
        print(f"❌ Ошибка обновления конфигурации: {e}")

def main():
    # Тестовые vless URL из удаленного файла
    test_urls = [
        "vless://b41a734c-e6d1-48c5-8677-c52ba40ec454@145.249.115.53:443?security=reality&encryption=none&flow=xtls-rprx-vision&type=tcp&fp=random&pbk=FscaEWx0paNBzL7GWHj4Fll7Xc-KxdhKgTthBAnByWI&sni=pingless.com#Амстердам (СКОРОСТНАЯ СЕТЬ для WI-FI)",
        "vless://f1d0fff5-2a46-4d13-bf47-0c1b431363a0@lte.snowfallproject.site:443?security=reality&encryption=none&flow=xtls-rprx-vision&type=tcp&fp=chrome&pbk=dhTXgiFZvZPJSNc33EqNvn_CRor_RKeiMxSkHsEdDic&sni=m.vk.com&sid=418ed2065470c8fa#Моб. операторы #5"
    ]
    
    config_path = "/Users/ghost/Documents/VCODE/SERVER_VLESS/client-config.json"
    
    print("🔧 Тестирование парсера vless URL...")
    
    # Тестируем парсинг
    for i, url in enumerate(test_urls):
        print(f"\n📋 Тест {i+1}:")
        config = parse_vless_url(url)
        if config:
            print(f"UUID: {config['uuid']}")
            print(f"Адрес: {config['address']}:{config['port']}")
            print(f"Безопасность: {config['security']}")
            print(f"SNI: {config['sni']}")
        else:
            print("❌ Ошибка парсинга")
    
    # Обновляем конфигурацию (раскомментируйте для реального обновления)
    # update_vless_config(config_path, test_urls)

if __name__ == "__main__":
    main()

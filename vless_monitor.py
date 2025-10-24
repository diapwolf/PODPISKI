#!/usr/bin/env python3
"""
Система мониторинга vless ключей
Автоматически отключает ключи при удалении файлов из репозитория
"""

import os
import json
import subprocess
import time
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, parse_qs

class VlessMonitor:
    def __init__(self, repo_path: str, config_path: str):
        self.repo_path = Path(repo_path)
        self.config_path = Path(config_path)
        self.last_commit = None
        self.active_keys = set()
        
    def get_current_commit(self) -> Optional[str]:
        """Получить текущий коммит репозитория"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception as e:
            print(f"❌ Ошибка получения коммита: {e}")
            return None
    
    def get_vless_files(self) -> List[Path]:
        """Получить список файлов с vless ключами"""
        vless_files = []
        for file_path in self.repo_path.glob("*.txt"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'vless://' in content:
                        vless_files.append(file_path)
            except Exception as e:
                print(f"⚠️  Ошибка чтения файла {file_path}: {e}")
        return vless_files
    
    def extract_vless_urls(self, file_path: Path) -> List[str]:
        """Извлечь vless URL из файла"""
        urls = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Ищем все vless URL в файле
            vless_pattern = r'vless://[^\s\n]+'
            matches = re.findall(vless_pattern, content)
            urls.extend(matches)
            
        except Exception as e:
            print(f"❌ Ошибка чтения файла {file_path}: {e}")
        
        return urls
    
    def parse_vless_url(self, vless_url: str) -> Optional[Dict]:
        """Парсит vless URL и возвращает словарь с параметрами"""
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
            print(f"❌ Ошибка парсинга URL {vless_url}: {e}")
            return None
    
    def create_vless_outbound(self, vless_config: Dict, tag: str) -> Dict:
        """Создает outbound конфигурацию для vless"""
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
    
    def get_all_active_keys(self) -> List[str]:
        """Получить все активные vless ключи из всех файлов репозитория"""
        active_urls = []
        vless_files = self.get_vless_files()
        
        for file_path in vless_files:
            urls = self.extract_vless_urls(file_path)
            active_urls.extend(urls)
            print(f"📁 Файл {file_path.name}: найдено {len(urls)} ключей")
        
        return active_urls
    
    def load_config(self) -> Dict:
        """Загрузить конфигурацию vless клиента"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Ошибка загрузки конфигурации: {e}")
            return {}
    
    def save_config(self, config: Dict):
        """Сохранить конфигурацию vless клиента"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"💾 Конфигурация сохранена в {self.config_path}")
        except Exception as e:
            print(f"❌ Ошибка сохранения конфигурации: {e}")
    
    def update_config_with_keys(self, vless_urls: List[str]):
        """Обновить конфигурацию с новыми ключами"""
        config = self.load_config()
        
        if not config:
            print("❌ Не удалось загрузить конфигурацию")
            return
        
        # Создаем новые outbounds для каждого ключа
        new_outbounds = []
        
        for i, url in enumerate(vless_urls):
            vless_config = self.parse_vless_url(url)
            if vless_config:
                tag = f"vless-{i+1}"
                outbound = self.create_vless_outbound(vless_config, tag)
                new_outbounds.append(outbound)
                print(f"✅ Добавлен ключ {i+1}: {vless_config['address']}:{vless_config['port']}")
            else:
                print(f"❌ Ошибка парсинга ключа {i+1}")
        
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
        self.save_config(config)
    
    def check_and_update(self):
        """Проверить изменения и обновить конфигурацию"""
        current_commit = self.get_current_commit()
        
        if not current_commit:
            print("❌ Не удалось получить текущий коммит")
            return
        
        if current_commit != self.last_commit:
            print(f"🔄 Обнаружены изменения в репозитории: {current_commit[:8]}...")
            
            # Получаем активные ключи
            active_urls = self.get_all_active_keys()
            
            # Обновляем конфигурацию
            self.update_config_with_keys(active_urls)
            
            self.last_commit = current_commit
            self.active_keys = set(active_urls)
            
            print(f"📊 Активных ключей: {len(active_urls)}")
        else:
            print("✅ Изменений не обнаружено")
    
    def start_monitoring(self, interval: int = 30):
        """Запустить мониторинг изменений"""
        print(f"🚀 Запуск мониторинга репозитория {self.repo_path}")
        print(f"⏰ Интервал проверки: {interval} секунд")
        print("🛑 Нажмите Ctrl+C для остановки")
        print("-" * 50)
        
        try:
            while True:
                self.check_and_update()
                print("-" * 50)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n🛑 Мониторинг остановлен")

def main():
    # Пути к репозиторию и конфигурации
    repo_path = "/Users/ghost/Documents/VCODE/УПРАВЛЕНИЕ ПОДПИСКАМИ/PODPISKI"
    config_path = "/Users/ghost/Documents/VCODE/SERVER_VLESS/client-config.json"
    
    # Проверяем существование путей
    if not Path(repo_path).exists():
        print(f"❌ Репозиторий не найден: {repo_path}")
        return
    
    if not Path(config_path).exists():
        print(f"❌ Конфигурационный файл не найден: {config_path}")
        return
    
    # Создаем монитор
    monitor = VlessMonitor(repo_path, config_path)
    
    # Запускаем мониторинг
    monitor.start_monitoring(interval=30)

if __name__ == "__main__":
    main()

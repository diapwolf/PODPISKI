#!/bin/bash

# Скрипт для запуска мониторинга vless ключей
# Автоматически отключает ключи при удалении файлов из репозитория

echo "🚀 Запуск системы управления vless ключами..."

# Переходим в директорию скрипта
cd "$(dirname "$0")"

# Проверяем, что Python установлен
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 не найден. Установите Python3 для работы скрипта."
    exit 1
fi

# Проверяем, что Git установлен
if ! command -v git &> /dev/null; then
    echo "❌ Git не найден. Установите Git для работы с репозиторием."
    exit 1
fi

# Проверяем, что репозиторий существует
REPO_PATH="/Users/ghost/Documents/VCODE/УПРАВЛЕНИЕ ПОДПИСКАМИ/PODPISKI"
if [ ! -d "$REPO_PATH" ]; then
    echo "❌ Репозиторий не найден: $REPO_PATH"
    echo "Сначала клонируйте репозиторий PODPISKI"
    exit 1
fi

# Проверяем, что конфигурационный файл существует
CONFIG_PATH="/Users/ghost/Documents/VCODE/SERVER_VLESS/client-config.json"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "❌ Конфигурационный файл не найден: $CONFIG_PATH"
    echo "Создайте конфигурационный файл vless клиента"
    exit 1
fi

echo "✅ Все проверки пройдены"
echo "📁 Репозиторий: $REPO_PATH"
echo "⚙️  Конфигурация: $CONFIG_PATH"
echo ""

# Запускаем Python скрипт
echo "🔄 Запуск мониторинга..."
python3 vless_monitor.py

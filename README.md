Automated monitoring and response to threats

В работе реализован Python-скрипт, который использует два источника данных:
1. API Vulners для получения информации об уязвимостях.
2. Сымитированные логи безопасности в формате JSON:
   - winevent
   - dns
   - http

## Что делает скрипт
- получает данные об уязвимостях из Vulners API;
- анализирует логи безопасности;
- выявляет подозрительные события:
  - опасные уязвимости с высоким CVSS;
  - подозрительные Windows Event ID;
  - частые и аномальные DNS-запросы;
  - подозрительные HTTP-запросы и User-Agent;
- выполняет имитацию реагирования:
  - выводит сообщение вида [ALERT] Обнаружена угроза...
  - имитирует блокировку IP;
- сохраняет результаты в:
  - CSV-отчёт,
  - JSON-отчёт,
  - PNG-график.

## Запуск
Установить зависимости:

py -m pip install -r requirements.txt

### Установить переменную окружения с API-ключом Vulners
Windows PowerShell:
$env:VULNERS_API_KEY="your_api_key"

Windows CMD:
set VULNERS_API_KEY=your_api_key

Запуск:
python main.py

## Результат
После запуска в папке `reports/` создаются:
- report_YYYYMMDD_HHMMSS.csv
- report_YYYYMMDD_HHMMSS.json
- chart_YYYYMMDD_HHMMSS.png

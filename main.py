from __future__ import annotations

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Any

import requests
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch


# =========================================================
# Пути проекта
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
LOGS_PATH = BASE_DIR / "logs" / "demo_logs.json"
REPORTS_DIR = BASE_DIR / "reports"

# =========================================================
# Переменные окружения / API
# =========================================================
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

# =========================================================
# Настройки анализа
# =========================================================
VULNERS_QUERY = "openssl"
CVSS_LIMIT = 7.0

SUSPICIOUS_EVENT_IDS = {
    4625: "Неудачные попытки входа",
    4648: "Вход с использованием явных учетных данных",
    1102: "Очистка журнала аудита",
    4720: "Создание учетной записи",
}

SUSPICIOUS_DNS_DOMAINS = {
    "malicious-domain.com",
}

HTTP_SUSPICIOUS_KEYWORDS = [
    "sqlmap",
    "nikto",
]

HTTP_SUSPICIOUS_URLS = [
    "/admin",
    "/admin.php",
    "/wp-admin",
    "/login.php",
]

DNS_COUNT_THRESHOLD = 10

SEVERITY_COLORS = {
    "low": "#4CAF50",      # зелёный
    "medium": "#FF9800",   # оранжевый
    "high": "#E53935",     # красный
}


# =========================================================
# Вспомогательные функции
# =========================================================
def ensure_directories() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def load_logs(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Файл логов не найден: {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def normalize_ip(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def severity_by_score(score: float) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


# =========================================================
# Получение данных из Vulners API
# =========================================================
def fetch_vulners_data(query: str) -> list[dict[str, Any]]:
    if not VULNERS_API_KEY:
        raise EnvironmentError(
            "VULNERS_API_KEY не задан. Установи переменную окружения и запусти программу снова."
        )

    url = "https://vulners.com/api/v3/search/lucene/"
    headers = {
        "X-Api-Key": VULNERS_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {
        "query": query,
        "skip": 0,
        "size": 10,
        "fields": ["id", "title", "description", "cvss", "published"],
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()

        raw_items = data.get("data", {}).get("search", [])
        if isinstance(raw_items, dict):
            raw_items = list(raw_items.values())

        parsed_results: list[dict[str, Any]] = []

        for item in raw_items:
            source = item.get("_source", item)

            cvss_value = 0
            cvss_block = source.get("cvss", 0)

            if isinstance(cvss_block, dict):
                cvss_value = cvss_block.get("score", 0) or 0
            elif isinstance(cvss_block, (int, float)):
                cvss_value = cvss_block

            parsed_results.append(
                {
                    "id": source.get("id", "N/A"),
                    "title": source.get("title", "Без названия"),
                    "cvss": float(cvss_value),
                    "description": str(source.get("description", ""))[:250],
                }
            )

        if not parsed_results:
            raise ValueError("Vulners API вернул пустой список результатов.")

        return parsed_results

    except requests.exceptions.HTTPError as error:
        raise RuntimeError(
            f"Ошибка HTTP при запросе к Vulners API: {error}. "
            "Проверь правильность и актуальность API-ключа."
        ) from error
    except Exception as error:
        raise RuntimeError(f"Ошибка при запросе к Vulners API: {error}") from error


# =========================================================
# Анализ уязвимостей из API
# =========================================================
def analyze_vulnerabilities(vuln_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for item in vuln_data:
        cvss = float(item.get("cvss", 0))

        if cvss >= 9.0:
            severity = "high"
        elif cvss >= CVSS_LIMIT:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            {
                "target": item.get("id", ""),
                "type": "vulnerability",
                "source": "vulners_api",
                "error": "",
                "malicious": 1 if severity == "high" else 0,
                "suspicious": 1 if severity == "medium" else 0,
                "threat_score": cvss,
                "is_threat": cvss >= CVSS_LIMIT,
                "src_ip": "",
                "dest_ip": "",
                "description": item.get("title", ""),
                "severity": severity,
                "timestamp": "",
            }
        )

    return findings


# =========================================================
# Анализ Windows Event логов
# =========================================================
def analyze_winevent_logs(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for event in events:
        event_id = safe_int(event.get("event_id"))
        src_ip = normalize_ip(event.get("source_ip"))
        timestamp = str(event.get("timestamp", ""))
        description = str(event.get("description", ""))
        count = safe_int(event.get("count"), 1)

        if event_id in SUSPICIOUS_EVENT_IDS:
            base_score = 8 if event_id in (1102, 4648) else 6
            threat_score = base_score + max(0, count - 1)
            severity = severity_by_score(threat_score)

            findings.append(
                {
                    "target": f"event_id:{event_id}",
                    "type": "winevent",
                    "source": "simulated_logs",
                    "error": "",
                    "malicious": 1 if severity == "high" else 0,
                    "suspicious": 1 if severity == "medium" else 0,
                    "threat_score": threat_score,
                    "is_threat": True,
                    "src_ip": src_ip,
                    "dest_ip": "",
                    "description": f"{description}; count={count}",
                    "severity": severity,
                    "timestamp": timestamp,
                }
            )

    return findings


# =========================================================
# Анализ DNS логов
# =========================================================
def analyze_dns_logs(dns_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for record in dns_logs:
        query = str(record.get("query", "")).strip()
        src_ip = normalize_ip(record.get("src_ip"))
        count = safe_int(record.get("count"))
        timestamp = str(record.get("timestamp", ""))

        reasons: list[str] = []
        score = 0

        if query.lower() in SUSPICIOUS_DNS_DOMAINS:
            reasons.append("домен из списка подозрительных")
            score += 7

        if len(query) >= 25 and "." not in query:
            reasons.append("возможный DNS-туннель")
            score += 6

        if count >= DNS_COUNT_THRESHOLD:
            reasons.append(f"частые DNS-запросы ({count})")
            score += 4

        if reasons:
            severity = severity_by_score(score)

            findings.append(
                {
                    "target": query,
                    "type": "dns",
                    "source": "simulated_logs",
                    "error": "",
                    "malicious": 1 if severity == "high" else 0,
                    "suspicious": 1 if severity == "medium" else 0,
                    "threat_score": score,
                    "is_threat": True,
                    "src_ip": src_ip,
                    "dest_ip": "",
                    "description": "; ".join(reasons),
                    "severity": severity,
                    "timestamp": timestamp,
                }
            )

    return findings


# =========================================================
# Анализ HTTP логов
# =========================================================
def analyze_http_logs(http_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for record in http_logs:
        src_ip = normalize_ip(record.get("src_ip"))
        method = str(record.get("method", "")).strip().upper()
        url = str(record.get("url", "")).strip()
        status = str(record.get("status", "")).strip()
        user_agent = str(record.get("user_agent", "")).strip()
        timestamp = str(record.get("timestamp", ""))

        reasons: list[str] = []
        score = 0

        url_lower = url.lower()
        ua_lower = user_agent.lower()

        if any(keyword in ua_lower for keyword in HTTP_SUSPICIOUS_KEYWORDS):
            reasons.append(f"подозрительный User-Agent: {user_agent}")
            score += 7

        if any(suspicious_url in url_lower for suspicious_url in HTTP_SUSPICIOUS_URLS):
            reasons.append(f"доступ к чувствительному URL: {url}")
            score += 4

        if status in {"401", "403", "404"} and method in {"GET", "POST"}:
            reasons.append(f"подозрительный HTTP-ответ: {status}")
            score += 2

        if reasons:
            severity = severity_by_score(score)

            findings.append(
                {
                    "target": url,
                    "type": "http",
                    "source": "simulated_logs",
                    "error": "",
                    "malicious": 1 if severity == "high" else 0,
                    "suspicious": 1 if severity == "medium" else 0,
                    "threat_score": score,
                    "is_threat": True,
                    "src_ip": src_ip,
                    "dest_ip": "",
                    "description": "; ".join(reasons),
                    "severity": severity,
                    "timestamp": timestamp,
                }
            )

    return findings


# =========================================================
# Имитация реагирования
# =========================================================
def simulate_response(findings: list[dict[str, Any]]) -> None:
    print("\n=== ИМИТАЦИЯ РЕАГИРОВАНИЯ ===")

    threats = [row for row in findings if row.get("is_threat")]

    if not threats:
        print("Угроз не обнаружено.")
        return

    for row in threats:
        src_ip = row.get("src_ip") or "N/A"
        target = row.get("target") or "N/A"
        source = row.get("source") or "N/A"
        severity = row.get("severity") or "unknown"

        print(
            f"[ALERT] Обнаружена угроза от {source}. "
            f"IP: {src_ip}. Объект: {target}. Уровень: {severity}."
        )

        if src_ip and src_ip != "N/A":
            print(f"[ACTION] Имитация блокировки IP-адреса: {src_ip}")


# =========================================================
# DataFrame
# =========================================================
def build_dataframe(findings: list[dict[str, Any]]) -> pd.DataFrame:
    columns = [
        "target",
        "type",
        "source",
        "error",
        "malicious",
        "suspicious",
        "threat_score",
        "is_threat",
        "src_ip",
        "dest_ip",
        "description",
        "severity",
        "timestamp",
    ]

    if findings:
        dataframe = pd.DataFrame(findings)
    else:
        dataframe = pd.DataFrame(columns=columns)

    for column in columns:
        if column not in dataframe.columns:
            dataframe[column] = ""

    return dataframe[columns]


# =========================================================
# Сохранение отчётов
# =========================================================
def save_reports(dataframe: pd.DataFrame, stamp: str) -> tuple[Path, Path]:
    csv_path = REPORTS_DIR / f"report_{stamp}.csv"
    json_path = REPORTS_DIR / f"report_{stamp}.json"

    dataframe.to_csv(csv_path, index=False, encoding="utf-8-sig")
    dataframe.to_json(json_path, orient="records", force_ascii=False, indent=4)

    return csv_path, json_path


# =========================================================
# Построение одного PNG с двумя графиками
# =========================================================
def save_chart(dataframe: pd.DataFrame, stamp: str) -> Path:
    chart_path = REPORTS_DIR / f"chart_{stamp}.png"

    figure, axes = plt.subplots(1, 2, figsize=(18, 8))
    figure.suptitle("Отчёт об обнаружении угроз", fontsize=16, fontweight="bold")

    # ---------------- Левый график ----------------
    left_axis = axes[0]
    vulners_df = dataframe[
        (dataframe["source"] == "vulners_api") & (dataframe["is_threat"] == True)
    ].copy()

    if vulners_df.empty:
        left_axis.set_title("Vulners API — угрозы по CVSS")
        left_axis.text(
            0.5,
            0.5,
            "Нет данных от API",
            ha="center",
            va="center",
            transform=left_axis.transAxes,
        )
        left_axis.set_xlabel("Оценка угрозы")
        left_axis.set_ylabel("CVE")
    else:
        vulners_df = vulners_df.sort_values("threat_score", ascending=False).head(10)
        left_colors = [
            SEVERITY_COLORS.get(severity, "#999999")
            for severity in vulners_df["severity"]
        ]

        left_axis.barh(
            vulners_df["target"].astype(str),
            vulners_df["threat_score"],
            color=left_colors,
        )
        left_axis.set_title("Vulners API — угрозы по CVSS")
        left_axis.set_xlabel("Оценка угрозы (CVSS)")
        left_axis.set_ylabel("CVE")
        left_axis.invert_yaxis()

    # ---------------- Правый график ----------------
    right_axis = axes[1]
    logs_df = dataframe[
        (dataframe["source"] == "simulated_logs")
        & (dataframe["is_threat"] == True)
        & (dataframe["src_ip"].astype(str).str.len() > 0)
    ].copy()

    if logs_df.empty:
        right_axis.set_title("Логи — источники подозрительной активности")
        right_axis.text(
            0.5,
            0.5,
            "Нет данных из логов",
            ha="center",
            va="center",
            transform=right_axis.transAxes,
        )
        right_axis.set_xlabel("Количество событий")
        right_axis.set_ylabel("IP-адрес")
    else:
        grouped = (
            logs_df.groupby(["src_ip", "severity"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(10)
            .sort_values("count", ascending=True)
        )

        right_colors = [
            SEVERITY_COLORS.get(severity, "#999999")
            for severity in grouped["severity"]
        ]

        right_axis.barh(
            grouped["src_ip"].astype(str),
            grouped["count"],
            color=right_colors,
        )
        right_axis.set_title("Логи — источники подозрительной активности")
        right_axis.set_xlabel("Количество событий")
        right_axis.set_ylabel("IP-адрес")

    # ---------------- Легенда ----------------
    severity_legend = [
        Patch(facecolor=SEVERITY_COLORS["high"], label="Высокая"),
        Patch(facecolor=SEVERITY_COLORS["medium"], label="Средняя"),
        Patch(facecolor=SEVERITY_COLORS["low"], label="Низкая"),
    ]

    figure.legend(
        handles=severity_legend,
        loc="upper center",
        ncol=3,
        bbox_to_anchor=(0.5, 0.94),
        title="Уровень угрозы",
    )

    # ---------------- Критерии ----------------
    criteria_text = (
        "Критерии определения угроз:\n"
        "• Vulners API: CVSS >= 7.0 — угроза, CVSS >= 9.0 — высокая угроза.\n"
        "• Windows Events: 4625, 4648, 1102, 4720 считаются подозрительными.\n"
        "• DNS: подозрительный домен, длинный запрос без точки, частые запросы >= 10.\n"
        "• HTTP: sqlmap/nikto в User-Agent, доступ к /admin, /wp-admin, /login.php, коды 401/403/404.\n"
        "• Цвета: красный — высокая, оранжевый — средняя, зелёный — низкая."
    )

    figure.text(
        0.02,
        0.01,
        criteria_text,
        ha="left",
        va="bottom",
        fontsize=10,
        bbox=dict(boxstyle="round,pad=0.5", facecolor="#f5f5f5", edgecolor="#cccccc"),
    )

    plt.tight_layout(rect=[0, 0.14, 1, 0.9])
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()

    return chart_path


# =========================================================
# Главная функция
# =========================================================
def main() -> None:
    ensure_directories()

    print("=== Запуск итогового ДЗ ===")

    # 1. Загружаем логи
    logs_data = load_logs(LOGS_PATH)
    winevent_logs = logs_data.get("winevent", [])
    dns_logs = logs_data.get("dns", [])
    http_logs = logs_data.get("http", [])

    # 2. Получаем данные из API
    vulners_data = fetch_vulners_data(VULNERS_QUERY)

    # 3. Анализируем
    findings: list[dict[str, Any]] = []
    findings.extend(analyze_vulnerabilities(vulners_data))
    findings.extend(analyze_winevent_logs(winevent_logs))
    findings.extend(analyze_dns_logs(dns_logs))
    findings.extend(analyze_http_logs(http_logs))

    # 4. Оставляем итоговые значимые записи
    filtered_findings: list[dict[str, Any]] = []
    for row in findings:
        if row["source"] == "vulners_api":
            if float(row.get("threat_score", 0)) >= CVSS_LIMIT:
                filtered_findings.append(row)
        else:
            if bool(row.get("is_threat")):
                filtered_findings.append(row)

    # 5. Реагирование
    simulate_response(filtered_findings)

    # 6. Отчёты
    dataframe = build_dataframe(filtered_findings)
    stamp = now_stamp()

    csv_path, json_path = save_reports(dataframe, stamp)
    chart_path = save_chart(dataframe, stamp)

    print("\n=== ГОТОВО ===")
    print(f"CSV отчёт:  {csv_path}")
    print(f"JSON отчёт: {json_path}")
    print(f"PNG график: {chart_path}")
    print(f"Найдено записей: {len(dataframe)}")


if __name__ == "__main__":
    main()

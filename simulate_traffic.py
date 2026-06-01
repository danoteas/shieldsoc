"""
simulate_traffic.py
────────────────────
Симулирует нормальный легитимный трафик к платформе.
Имитирует нескольких пользователей которые просматривают дашборд.

Запуск (в отдельном терминале пока работает платформа):
    python simulate_traffic.py

Остановить: Ctrl+C
"""

import requests
import time
import random
import threading
import sys

TARGET = "http://192.168.20.8:8001"

PAGES = [
    "/",
    "/analytics",
    "/map",
    "/history",
    "/intelligence",
    "/sessions",
    "/api/events",
    "/api/blocked",
    "/api/sessions",
    "/api/traffic_series",
    "/api/attack_distribution",
]

def user_session(user_id: int, delay: float) -> None:
    """Имитирует одного пользователя который просматривает платформу."""
    session = requests.Session()
    count   = 0
    print(f"  User-{user_id} запущен (задержка {delay:.1f}с)")

    while True:
        try:
            page = random.choice(PAGES)
            session.get(f"{TARGET}{page}", timeout=3)
            count += 1
            if count % 10 == 0:
                print(f"  User-{user_id}: {count} запросов")
            time.sleep(random.uniform(delay * 0.5, delay * 1.5))
        except requests.exceptions.ConnectionError:
            print(f"  User-{user_id}: платформа недоступна, retry 3s...")
            time.sleep(3)
        except Exception:
            time.sleep(delay)


def burst_user(user_id: int) -> None:
    """Иногда делает бёрст из 5-10 запросов подряд, потом пауза."""
    session = requests.Session()
    print(f"  Burst-{user_id} запущен")

    while True:
        try:
            # Burst: 5-15 запросов быстро
            burst_size = random.randint(5, 15)
            for _ in range(burst_size):
                page = random.choice(PAGES[:6])  # только основные страницы
                session.get(f"{TARGET}{page}", timeout=2)
                time.sleep(random.uniform(0.05, 0.2))

            # Пауза 10-30 секунд
            pause = random.uniform(10, 30)
            time.sleep(pause)
        except Exception:
            time.sleep(5)


def main():
    print("=" * 55)
    print("  Traffic Simulator — ShieldSOC")
    print(f"  Target: {TARGET}")
    print("=" * 55)

    # Проверяем доступность платформы
    print("\nПроверяю доступность платформы...")
    try:
        r = requests.get(f"{TARGET}/", timeout=5)
        print(f"✅ Платформа доступна (HTTP {r.status_code})")
    except Exception as e:
        print(f"❌ Платформа недоступна: {e}")
        print(f"   Убедись что uvicorn запущен на {TARGET}")
        sys.exit(1)

    print("\nЗапускаю симуляцию трафика...")
    print("Ctrl+C для остановки\n")

    threads = []

    # 3 обычных пользователя с разными задержками
    for i, delay in enumerate([1.0, 1.5, 2.0], start=1):
        t = threading.Thread(
            target=user_session,
            args=(i, delay),
            daemon=True
        )
        t.start()
        threads.append(t)
        time.sleep(0.5)  # небольшая задержка между запуском

    # 1 burst пользователь
    t = threading.Thread(target=burst_user, args=(4,), daemon=True)
    t.start()
    threads.append(t)

    print(f"\nЗапущено {len(threads)} пользователей")
    print("Трафик генерируется... (ожидай 10-15с для появления событий)")

    try:
        while True:
            time.sleep(10)
            print(f"[{time.strftime('%H:%M:%S')}] Симуляция работает...")
    except KeyboardInterrupt:
        print("\nОстановлено.")


if __name__ == "__main__":
    main()

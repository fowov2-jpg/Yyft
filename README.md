# SecureConnect — бесплатный рейтинг публичных VPN

Этот репозиторий предназначен для **проверки заранее заданных публичных источников** через ограниченные GitHub Actions и публикации только безопасных метаданных в `feed.json`.

- Проверяемые протоколы: VLESS, VMess, Trojan, Shadowsocks через официальный Xray-core.
- Не публикуются VPN URI, пароли и ключи. Только SHA-256 fingerprint исходной ссылки без фрагмента, дата проверки и результат HTTPS/YouTube-page.
- При отсутствии успешных проверок feed содержит пустой список, а не фиктивные успехи.
- Ограничение бюджета: **0 ₽**. GitHub может ограничить такую нагрузку или отключить расписание; не использовать обход ограничений.
- Исходники и тесты лежат прямо в репозитории: `checker.py`, `tests/`, `.github/workflows/verify-nodes.yml`. Полный ZIP Android-проекта передан владельцу в чате; Android-приложение само по себе в этот репозиторий не загружается.

## Начало работы

1. `Settings → Pages → Build and deployment → Source: GitHub Actions`.
2. `Actions → Public VPN ranking → Run workflow`.
3. Дождитесь успешных jobs `verify` и `deploy`; проверьте публичный JSON.
4. URL после успешного деплоя: `https://fowov2-jpg.github.io/Yyft/feed.json`. **До проверки HTTP 200 это только предполагаемый адрес.**
5. В Android SecureConnect укажите его в настройке публичного рейтинга.

Полная инструкция внутри архива `README_RU.md`.

[Проверки / Actions](https://github.com/fowov2-jpg/Yyft/actions) · [Настройка Pages](https://github.com/fowov2-jpg/Yyft/settings/pages)

**Важно:** Cloud `https_ok` повышает приоритет выбора, но приложение обязано локально перепроверять сервер. `youtube_page_ok` не подтверждает скорость 720p и не доказывает отсутствие утечек.

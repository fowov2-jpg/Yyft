# SecureConnect — бесплатный рейтинг публичных VPN

Этот репозиторий предназначен для **проверки заранее заданных публичных источников** через ограниченные GitHub Actions и публикации только безопасных метаданных в `feed.json`.

- Проверяемые протоколы: VLESS, VMess, Trojan, Shadowsocks через официальный Xray-core.
- Не публикуются VPN URI, пароли и ключи. Только SHA-256 fingerprint исходной ссылки без фрагмента, дата проверки и результат HTTPS/YouTube-page.
- При отсутствии успешных проверок feed содержит пустой список, а не фиктивные успехи.
- Ограничение бюджета: **0 ₽**. GitHub может ограничить такую нагрузку или отключить расписание; не использовать обход ограничений.
- Исходники и тесты лежат прямо в репозитории: `checker.py`, `tests/`, `.github/workflows/verify-nodes.yml`. Полный ZIP Android-проекта передан владельцу в чате; Android-приложение само по себе в этот репозиторий не загружается.

## Начало работы

1. Файл уже доступен через **[GitHub raw](https://raw.githubusercontent.com/fowov2-jpg/Yyft/main/feed.json)**; обновляется автоматически отдельным job `publish-raw` после проверок.
2. Чтобы включить **GitHub Pages**, выберите `Settings → Pages → Build and deployment → Source: GitHub Actions`.
3. `Actions → Public VPN ranking → Run workflow`, либо перезапустите упавший `deploy` последнего run.
4. Дождитесь успешных jobs `verify`, `publish-raw` и `deploy`; проверьте оба URL.
5. URL после успешного деплоя: `https://fowov2-jpg.github.io/Yyft/feed.json`. **До проверки HTTP 200 это только предполагаемый адрес.**
6. В Android SecureConnect raw feed из этого репозитория уже задан по умолчанию; после включения Pages его можно переключить на github.io.

Полная инструкция внутри архива `README_RU.md`.

[Проверки / Actions](https://github.com/fowov2-jpg/Yyft/actions) · [Настройка Pages](https://github.com/fowov2-jpg/Yyft/settings/pages)

**Важно:** Cloud `https_ok` повышает приоритет выбора, но приложение обязано локально перепроверять сервер. `youtube_page_ok` не подтверждает скорость 720p и не доказывает отсутствие утечек.

Первый Actions-run [№ 1](https://github.com/fowov2-jpg/Yyft/actions/runs/40227569438) проверил 80 кандидатов, 28 успешно. Второй [№ 2](https://github.com/fowov2-jpg/Yyft/actions/runs/40228043207) подтвердил автоматическое обновление `feed.json`. Job `deploy` до активации Pages возвращает 404 — не считайте GitHub Pages уже включённым.

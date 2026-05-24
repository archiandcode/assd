# URL Generator для PDF на Go

Небольшой Go-сервис для загрузки PDF-файлов и генерации отдельных URL.

## Запуск локально

Скопируйте или отредактируйте настройки в `.env`, затем запустите сервисы:

```bash
docker compose up -d --build
```

Создайте первого пользователя панели. Команда сработает только если таблица
`users` пустая:

```bash
docker compose run --rm app create-user admin 'change-this-password'
```

После запуска откройте `http://localhost:8010`.

Для запуска без Docker можно поднять только PostgreSQL:

```bash
docker compose up -d postgres
DATABASE_URL='postgres://url_generator:url_generator_password@localhost:5432/url_generator?sslmode=disable' \
go run .
```

По умолчанию локальный запуск без `DATABASE_URL` подключается к PostgreSQL
через Unix socket `/tmp/url-generator-postgres`.
Можно задать другой адрес базы:

```bash
DATABASE_URL='postgres://user:password@localhost:55432/dbname?sslmode=disable' go run .
```

Если порт занят:

```bash
PORT=8011 go run .
```

## URL

- `/login` - вход
- `/logout` - выход
- `/` - форма загрузки PDF-файлов или ZIP-архива с PDF
- `/uploads` - список загруженных PDF
- `/ws/uploads.xlsx` - websocket-выгрузка XLSX со всеми загруженными PDF
- `/{id}` - страница сайта для чтения документа
- `/{id}/inline` - PDF для чтения в браузере
- `/{id}/download` - скачивание PDF

Можно выбрать несколько PDF сразу или загрузить ZIP-архив. Для каждого PDF будет создан отдельный URL
с уникальным случайным кодом из 5 символов.

На странице `/uploads` есть кнопка выгрузки XLSX. Файл скачивается через
websocket; первая колонка содержит имя PDF без расширения `.pdf`, вторая -
5-символьный код ссылки.

Файлы сохраняются в `storage/files`, метаданные - в `storage/meta`,
пользователи авторизации - в PostgreSQL. Таблица пользователей создается
миграцией из `migrations`.

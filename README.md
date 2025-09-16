# ib-lab1

Безопасное REST API, построенное на FastAPI, SQLAlchemy и SQLite. Реализует JWT аутентификацию, базовые защиты в соответствии с OWASP Top 10 и CI пайплайн с SAST/SCA.

## Технологический стек
- Python 3.11
- FastAPI + Uvicorn
- SQLAlchemy 2.x + SQLite
- Аутентификация: JWT (PyJWT), хеширование паролей (passlib[bcrypt])
- Санитизация XSS: bleach
- Инструменты: uv (менеджер пакетов/запуск), ruff, black, pytest

## Как запустить локально
1. Установить зависимости
```bash
uv sync
```
2. Запустить сервер
```bash
uv run uvicorn app.main:app --reload
```
3. Swagger UI доступен по адресу `/docs`.

Переменные окружения:
- `DATABASE_URL` (опционально): например `sqlite:///./app.db` (по умолчанию)
- `JWT_SECRET`
- `JWT_EXP_MIN` (по умолчанию: 60)

## API

### Аутентификация
- POST `/auth/register` — создать пользователя
  - Запрос: `{ "username": string(3-100), "password": string(6-200) }`
  - Ответ: `UserOut { id, username, created_at }`

- POST `/auth/login` — аутентификация
  - Запрос: `{ "username": string, "password": string }`
  - Ответ: `Token { access_token, token_type }`

Используйте заголовок `Authorization: Bearer <token>` для защищенных эндпоинтов.

### Посты (защищенные)
- GET `/api/posts` — список постов
  - Ответ: `PostOut[]` (заголовок/содержимое санитизированы)

- POST `/api/posts` — создать пост
  - Запрос: `{ "title": string(1-200), "content": string(1-4000) }`
  - Ответ: `PostOut`

## Меры безопасности
- SQL Injection: SQLAlchemy ORM с привязанными параметрами; без конкатенации строк SQL.
- XSS: посты санитизируются через `bleach`
- Broken Authentication: JWT-аутентификация с использованием `Authorization: Bearer` с истечением срока действия и HMAC подписью; надежное хеширование паролей с помощью `passlib[bcrypt]`.
- Хранение паролей: хранятся только bcrypt хеши; без открытого текста.

## Тестирование
Интеграционные тесты с использованием `pytest` и `fastapi.testclient`:
```bash
uv run pytest -q
```
Тесты проверяют:
- Регистрацию и вход
- Доступ к `/api/posts` с защитой токеном
- Санитизацию XSS в ответах
- Защита от SQL инъекций

## CI/CD
GitHub Actions workflow `.github/workflows/ci.yml` запускается при push/PR в `main`:
- Ruff линтинг
- Black проверка форматирования
- Pytest
- SAST: Bandit
- SCA: Safety

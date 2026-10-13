# Електронний деканат — практичні №1 і №2

**Автор:** Бегулецький Дмитро, група 223з.  
**Дисципліна:** Безпека інформаційних систем.

## Функції
FastAPI, SQLite, Alembic, RBAC, bcrypt, JWT access/refresh, CORS, заголовки безпеки, rate limit, Fernet-шифрування email/phone, HMAC blind index, журнал аудиту 5W, детектор brute force, шифровані бекапи, Docker hardening, Nginx HTTPS.

## Запуск із чистого клону
1. Створіть `.env` з `.env.example`. Згенеруйте ключі: `python -m scripts.generate_key` (або в іншому Python з пакетом `cryptography`). Заповніть також три тестові паролі (не використовуйте реальні).
2. `bash scripts/generate_cert.sh` (потрібен OpenSSL; Git Bash на Windows).
3. `docker compose up -d --build`
4. `docker compose exec api alembic upgrade head`
5. `docker compose exec api python -m app.seed`
6. Відкрийте `https://localhost/docs` (сертифікат self-signed, браузер покаже попередження). Локально також доступний `http://127.0.0.1:8000/docs`.

**Увага:** не запускати `docker compose down -v`: це видалить дані. Для наявної БД із ЗПР-1 міграція додає шифровані поля, але не створює історичні email, бо їх у вихідній моделі не було.

## Авторизація
POST `/auth/login` приймає JSON `{"username":"admin","password":"<пароль із .env>"}`. Отриманий `access_token` передайте у заголовку `Authorization: Bearer <token>`; у Swagger кнопка Authorize використовує bearer. Доступні `/auth/me`, `/auth/refresh`, `/auth/register`, `/students`, `/teachers`, `/admin/users`, `/admin/audit-log`, `/admin/security-stats`, `/health`.

## Бекап
`docker compose exec api python -m scripts.backup_db`; зашифрований файл з'явиться в `data/backups`. Перевірка: `docker compose exec api python -m scripts.restore_db /data/backups/<filename>.db.enc`.

## Перевірки
- Студент GET `/admin/audit-log` → 403.
- П'ять неправильних логінів → запис `login_failed`; після паузи ліміту запит → 429 та `brute_force_detected`.
- `https://localhost/health` → 200; `http://localhost/health` → 301.
- `docker compose exec api id` → UID 1000.
- `docker compose exec api python -m scripts.backup_db` → `.enc`.

Звіти: `SECURITY_AUDIT.md`, `docs/Звіт_практична_2.docx`. Результати тестів і сканування необхідно підтвердити локальним запуском.
## Результати тестування безпеки

Під час перевірки REST API підтверджено:
- Успішну авторизацію адміністратора.
- Розмежування прав доступу за ролями (RBAC).
- Відмову студенту в доступі до /admin/users (HTTP 403).
- Роботу журналу аудиту (HTTP 200).
- Шифрування та розшифрування тестових даних.
- Створення зашифрованої резервної копії SQLite.
- Успішне відновлення резервної копії (integrity_check: ok).
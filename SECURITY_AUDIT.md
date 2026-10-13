# SECURITY AUDIT — Електронний деканат, ЗПР-2

Автор: Бегулецький Дмитро, група 223з. Статус: **підготовлено до локального аудиту; реальний Docker-запуск і сканування ще не підтверджені**.

## Обсяг
FastAPI/SQLite/Alembic; шифрування персональних даних, RBAC, JWT, аудит, Docker/Nginx.

## STRIDE та матриця ризиків
| Загроза | STRIDE | Ймовірність (1–5) | Вплив (1–5) | Ризик | Захід |
|---|---|---:|---:|---:|---|
| Підбір паролів | Spoofing | 4 | 4 | 16 | Rate limit + detector + журнал |
| Викрадення БД | Information Disclosure | 3 | 5 | 15 | Fernet + blind index + бекап |
| Підробка журналу | Repudiation/Tampering | 3 | 4 | 12 | Аудит 5W; потрібне зовнішнє сховище логів |
| Відмова сервісу | Denial of Service | 3 | 3 | 9 | Rate limit; ризик блокування чужого акаунта |
| Зловживання роллю | Elevation of Privilege | 3 | 5 | 15 | RBAC, 403 для студента |
| Компрометація контейнера | Elevation of Privilege | 3 | 4 | 12 | non-root, read-only, cap_drop |

## OWASP Top 10 (2021) — попередній чекліст
A01 Broken Access Control: RBAC на адмін-API; потрібен retest. A02 Cryptographic Failures: Fernet, bcrypt, TLS. A03 Injection: ORM і валідація Pydantic; потрібен SAST. A04 Insecure Design: STRIDE. A05 Security Misconfiguration: HTTPS, security headers, non-root. A06 Vulnerable Components: потрібен Trivy/SCA. A07 Authentication Failures: JWT і brute-force detector. A08 Integrity Failures: потрібен контроль CI. A09 Logging Failures: audit_log і stdout. A10 SSRF: зовнішні URL у поточному API відсутні.

## Команди для перевірки
```bash
docker compose up -d --build
docker compose exec api alembic upgrade head
docker compose exec api python -m app.seed
docker compose exec api id
docker compose exec api python -m scripts.backup_db
curl -k -I https://localhost/health
curl -I http://localhost/health
```

## Сканування (запустити на своєму ПК)
```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image information-security-practice-api
# За потреби уточнити ім'я образу через docker compose images
```
Bandit: `docker compose exec api sh -c 'pip install bandit && bandit -r app -f json -o /tmp/bandit.json'` (звіт усередині контейнера). SCA: `docker compose exec api sh -c 'pip install pip-audit && pip-audit'`.

## Результати та ретест
| Тест | Очікується | Фактично | Статус |
|---|---|---|---|
| HTTPS /health | 200 | Не перевірено | Pending |
| HTTP redirect | 301 | Не перевірено | Pending |
| RBAC student /admin/audit-log | 403 | Не перевірено | Pending |
| Brute force | 429 + event | Не перевірено | Pending |
| Fernet у БД | ciphertext | Не перевірено | Pending |
| Backup restore | integrity_check=ok | Не перевірено | Pending |
| Trivy / Bandit / SCA | Звіт сканування | Не виконано | Pending |

## Залишкові ризики
Self-signed TLS лише для localhost; SQLite не є SIEM; журнали не захищені від адміністратора БД; детектор у разі атак може заблокувати легітимний акаунт; IP forwarding вимагає перевірки довірених проксі; зміна ключа Fernet потребує процедури re-encryption.

## Висновок
Підготовлено навчальну реалізацію захисних механізмів. Фінальний висновок про ефективність можливий лише після фактичного запуску тестів, сканування та документування результатів.

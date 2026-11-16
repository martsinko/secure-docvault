# Secure DocVault

Навчальний проєкт з дисципліни «Технології захисту інформаційних ресурсів».

## Реалізовані шари захисту

1. Безпечна реєстрація, bcrypt і параметризовані SQLite-запити.
2. JWT access/refresh tokens з ротацією та відкликанням.
3. Санітизація HTML, CSP, security headers і обмежений CORS.
4. Сигнатурний micro-WAF, greylist та rate limiter.
5. AES-256-GCM зашифроване файлове сховище.
6. RSA-PSS цифрові підписи та верифікація документа.

## Запуск у VS Code

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
.venv/bin/python scripts/generate_secrets.py
.venv/bin/uvicorn app.main:app --reload
```

Відкрийте `http://127.0.0.1:8000/docs`. Перед запуском у production замініть секрети у `.env` та налаштуйте HTTPS на reverse proxy.

## Перевірки

```bash
.venv/bin/pytest -q
```

Не додавайте `.env`, ключі, базу даних або зашифровані документи до Git.

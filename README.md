# Skill Swap Platform

Flask-based peer-to-peer learning platform where users exchange skills, send swap requests, become friends after accepted swaps, and chat.

## Team

1. Pandey Aayush Vijay (`aayushpandey5806@gmail.com`)
2. Jain Nirav Nilesh (`niravjain1382005@gmail.com`)
3. Meet K Nagar (`meetnagar847@gmail.com`)

## Features

- Auth: register, login, logout, hashed passwords
- Profile: name, location, availability, visibility, offered/wanted skills
- Browse: public profiles with search, location filter, availability filter, pagination
- Swap workflow: send, accept, reject, cancel; request status tracking
- Friends & chat: accepted swaps create friend connections with 1:1 chat
- Support / query system: submit tickets, view history, resolve/reopen/close own tickets
- Admin support dashboard: filter all tickets and update statuses (`open`, `in_progress`, `resolved`, `closed`)
- Smart suggestions: skill + location autocomplete across profile/browse/support
- Home engagement sections: recommendations, trending skills, achievements, activity snapshot
- CSRF protection + `.env` config + Railway-friendly startup (`gunicorn`, `PORT`, Postgres URL support)

## Stack

- Flask, Flask-SQLAlchemy, Flask-Login, Flask-Bcrypt, Flask-WTF
- SQLite (default local) / PostgreSQL (recommended for Railway)
- Jinja templates + HTML/CSS/JS
- Gunicorn (deployment)
- Pytest (tests)

## Data Model

- `User`
- `Skill` (`offered` / `wanted`)
- `SwapRequest`
- `Connection` (friends)
- `Message` (chat)
- `SupportTicket`

## Quick Start (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python skillswap/app.py
```

App URL: `http://127.0.0.1:5000`

## Key `.env` Variables

- `APP_ENV` (`development` / `production`)
- `FLASK_DEBUG`
- `SECRET_KEY`
- `DATABASE_URL`
- `APP_HOST`, `APP_PORT` (local run)
- `SESSION_COOKIE_SECURE`, `REMEMBER_COOKIE_SECURE`
- `WTF_CSRF_ENABLED`, `WTF_CSRF_TIME_LIMIT`
- `ADMIN_EMAILS` (comma-separated admin emails for `/admin/support`)

## Main Pages

- `/` home (recommendations / trends / engagement)
- `/health`
- `/login`, `/register`
- `/profile`
- `/browse`
- `/swap-requests`
- `/friends`
- `/chat/<connection_id>`
- `/support`
- `/admin/support` (admin only)

## Key APIs

- Auth/Profile: `POST /api/login`, `GET /api/get_profile`, `POST /api/update_profile`
- Browse/Swaps: `GET /skills/offered`, `POST /swap_request`, `POST /respond_swap/<id>`, `GET /api/swap_requests`
- Friends/Chat: `GET /api/friends`, `GET/POST /api/chat/<connection_id>/messages`
- Support: `GET/POST /api/support_tickets`, `PATCH /api/support_tickets/<id>`
- Admin Support: `GET /api/admin/support_tickets`, `PATCH /api/admin/support_tickets/<id>`
- Suggestions: `GET /api/suggestions/locations`, `GET /api/suggestions/skills`

## Railway (recommended)

- Set Start Command:
```bash
gunicorn -b 0.0.0.0:$PORT skillswap.app:app
```
- Use PostgreSQL and set `DATABASE_URL`
- Set production vars: `APP_ENV=production`, `FLASK_DEBUG=0`, secure cookie flags, strong `SECRET_KEY`

## Tests

```powershell
.venv\Scripts\python.exe -m pytest -q
```

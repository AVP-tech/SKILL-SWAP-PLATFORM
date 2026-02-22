# Skill Swap Platform

Flask web app for exchanging skills with other users. Create a profile, list what you offer/want, browse public profiles, and manage swap requests.

## Team

1. Pandey Aayush Vijay (`aayushpandey5806@gmail.com`)
2. Jain Nirav Nilesh (`niravjain1382005@gmail.com`)
3. Meet K Nagar (`meetnagar847@gmail.com`)

## Features

- Register / login (hashed passwords)
- Profile management (name, location, availability, public/private visibility)
- Skills offered + skills wanted
- Browse public profiles with search, filters, and pagination
- Send swap requests
- Accept / reject / cancel requests
- CSRF protection for forms and POST API actions
- `.env`-based config + production-safe cookie defaults

## Stack

- Flask, Flask-SQLAlchemy, Flask-Login, Flask-Bcrypt, Flask-WTF
- SQLite (default)
- Jinja templates + HTML/CSS/JS

## Data Model

- `User`: profile + auth fields
- `Skill`: one record per user skill type (`offered` / `wanted`)
- `SwapRequest`: requester, target, status, timestamps

## Quick Start

```bash
python -m venv .venv
```

Windows (PowerShell):

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python skillswap/app.py
```

App URL: `http://127.0.0.1:5000`

## Config (`.env`)

Key variables:

- `APP_ENV` (`development` / `production`)
- `FLASK_DEBUG`
- `APP_HOST`, `APP_PORT`
- `SECRET_KEY`
- `DATABASE_URL`
- `SESSION_COOKIE_SECURE`, `REMEMBER_COOKIE_SECURE`
- `WTF_CSRF_ENABLED`, `WTF_CSRF_TIME_LIMIT`

## Main Routes

- `/` Home
- `/login`, `/register`
- `/profile` (login required)
- `/browse` (login required)
- `/swap-requests` (login required)

## Main API Endpoints

- `POST /api/login`
- `GET /api/get_profile`
- `POST /api/update_profile`
- `GET /skills/offered` (supports `q`, `location`, `availability`, `page`, `per_page`)
- `POST /swap_request`
- `POST /respond_swap/<request_id>`
- `GET /api/swap_requests`

## Tests

```bash
pytest -q
```

Current tests cover core auth/profile/swap workflows.

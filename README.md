# PhishGuard 🛡️

**Production-grade cybersecurity SaaS platform for phishing URL detection, SMS fraud analysis, and file content scanning.**

Built on top of two proven detection engines wrapped in a secure, scalable web architecture.

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    Nginx     │────▶│  Next.js 14 │     │  FastAPI    │
│ (Reverse    │     │  Frontend   │────▶│  Backend    │
│  Proxy +    │────▶│  TypeScript │     │  Python 3.11│
│  Rate Limit)│     │  TailwindCSS│     │  SQLAlchemy │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                                │
                         ┌──────────────────────┼──────────────────┐
                         │                      │                  │
                  ┌──────▼──────┐      ┌────────▼───────┐  ┌──────▼──────┐
                  │ PostgreSQL  │      │     Redis      │  │  Encrypted  │
                  │  Database   │      │   (Caching /   │  │  File Store │
                  │             │      │   Rate Limit)  │  │  AES-256    │
                  └─────────────┘      └────────────────┘  └─────────────┘
```

## Detection Engines

### URL Phishing Detector (`url_service.py`)
- Wraps `url_detector_core.py` (RandomForest ML model)
- Extracts 9 URL features: length, dots, hyphens, IP address, HTTPS, suspicious words, etc.
- Trained on 2 phishing datasets; loads from `model.pkl` on startup
- Returns: `label`, `confidence`, `reasons`, `detection_mode` (rule-based/ml-pattern/safe)

### SMS Fraud Detector (`message_service.py`)
- Wraps `sms_detector_core.py` (rule-based + OpenAI hybrid)
- 40+ regex rules covering OTP theft, bank fraud, prize scams, KYC fraud, threats
- Auto-detects language; translates non-English messages before scanning
- Calls OpenAI GPT-4o-mini when rule confidence is low
- Returns: `final_label`, `final_score`, `rule_score`, `reasons`, `language`

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| Authentication | JWT access + refresh tokens |
| Password hashing | bcrypt (12 rounds) |
| File encryption | AES-256-CBC |
| Access control | Role-based (user/analyst/admin) |
| Rate limiting | Nginx + SlowAPI |
| Audit logging | PostgreSQL audit_logs table |
| Input validation | Pydantic v2 schemas |

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB+ RAM (for ML model training)

### 1. Clone and configure

```bash
git clone https://github.com/yourorg/phishguard.git
cd phishguard
cp .env.example .env
# Edit .env — set strong passwords and secret keys
```

### 2. Add training datasets (required for URL detection)

Place these CSV files in `backend/data/`:
- `dataset_link_phishing.csv` — columns: `url`, `status` (phishing/legitimate)
- `phishing_url_dataset_unique.csv` — columns: `url`, `label` (0=safe, 1=phishing)

These can be sourced from Kaggle phishing URL datasets.

### 3. Start all services

```bash
docker compose up -d
```

The first run will train the ML model (takes 1-3 minutes).

### 4. Access the platform

| Service | URL |
|---------|-----|
| Frontend | http://localhost |
| API Docs | http://localhost/api/docs |
| API ReDoc | http://localhost/api/redoc |

---

## API Reference

### Authentication
```
POST /api/v1/auth/register    — Create account
POST /api/v1/auth/login       — Login (returns JWT tokens)
POST /api/v1/auth/refresh     — Refresh access token
GET  /api/v1/auth/me          — Current user info
```

### Scanning
```
POST /api/v1/scan/url         — Scan URL for phishing
POST /api/v1/scan/message     — Scan text for fraud
POST /api/v1/scan/file        — Upload file for scanning
```

### User
```
GET  /api/v1/user/history     — Paginated scan history
GET  /api/v1/user/stats       — User scan statistics
GET  /api/v1/user/profile     — User profile
```

### Admin (admin role required)
```
GET    /api/v1/admin/stats          — Platform statistics
GET    /api/v1/admin/users          — List all users
PATCH  /api/v1/admin/users/{id}/role   — Update user role
PATCH  /api/v1/admin/users/{id}/toggle — Enable/disable user
GET    /api/v1/admin/logs           — Audit logs
GET    /api/v1/admin/scans          — All scans (filterable)
```

---

## Project Structure

```
phishguard/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app + lifespan
│   │   ├── config.py            # Pydantic settings
│   │   ├── database.py          # SQLAlchemy engine
│   │   ├── models/models.py     # DB models (User, Scan, File, AuditLog)
│   │   ├── schemas/schemas.py   # Request/response validation
│   │   ├── routes/
│   │   │   ├── auth.py          # Register, login, refresh
│   │   │   ├── scan.py          # URL, message, file scan endpoints
│   │   │   ├── user.py          # History, profile, stats
│   │   │   └── admin.py         # Admin dashboard endpoints
│   │   ├── services/
│   │   │   ├── url_service.py         # URL detection wrapper
│   │   │   ├── url_detector_core.py   # Original ML detector (unchanged)
│   │   │   ├── message_service.py     # Message detection wrapper
│   │   │   ├── sms_detector_core.py   # Original rule engine (unchanged)
│   │   │   └── file_service.py        # Encrypted upload + background scan
│   │   ├── security/auth.py     # JWT, bcrypt, RBAC
│   │   └── utils/
│   │       ├── encryption.py    # AES-256 file encryption
│   │       └── audit.py         # Audit logging helper
│   ├── data/                    # Place training CSV datasets here
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/app/
│   │   ├── page.tsx             # Landing page
│   │   ├── auth/login/          # Login page
│   │   ├── auth/register/       # Register page
│   │   └── dashboard/
│   │       ├── layout.tsx       # Sidebar navigation
│   │       ├── page.tsx         # Dashboard home with charts
│   │       ├── url/page.tsx     # URL scanner
│   │       ├── message/page.tsx # Message scanner
│   │       ├── file/page.tsx    # File upload scanner
│   │       ├── history/page.tsx # Scan history table
│   │       └── admin/page.tsx   # Admin panel
│   ├── src/lib/
│   │   ├── api.ts               # Axios client + all API calls
│   │   └── store.ts             # Zustand auth state
│   └── Dockerfile
├── nginx/nginx.conf             # Reverse proxy + rate limiting
├── docker-compose.yml
├── .env.example
└── .github/workflows/ci.yml    # GitHub Actions CI/CD
```

---

## HTTPS / Production Deployment

1. Obtain SSL certificate (Let's Encrypt):
   ```bash
   certbot certonly --standalone -d yourdomain.com
   ```

2. Copy certs to `nginx/ssl/`

3. Uncomment the HTTPS server block in `nginx/nginx.conf`

4. Update `DOMAIN` in `.env`

5. Redeploy: `docker compose up -d`

---

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `POSTGRES_PASSWORD` | PostgreSQL password | Yes |
| `REDIS_PASSWORD` | Redis password | Yes |
| `JWT_SECRET_KEY` | JWT signing key (32+ chars) | Yes |
| `SECRET_KEY` | App secret key | Yes |
| `ENCRYPTION_KEY` | AES-256 key (base64) | No (auto-derived) |
| `OPENAI_API_KEY` | For AI-enhanced SMS scanning | No |
| `DOMAIN` | Production domain | For SSL |

---

## Roles

| Role | Permissions |
|------|-------------|
| `user` | Scan URLs, messages, files; view own history |
| `analyst` | Same as user + access to detailed scan data |
| `admin` | Full access: user management, audit logs, all scans |

---

## License

MIT License — see LICENSE file.

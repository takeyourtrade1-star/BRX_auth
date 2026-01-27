# Authentication Microservice

Enterprise-grade authentication microservice built with Python FastAPI, PostgreSQL 16, and Redis.

## Features

- **JWT RS256 Authentication** - Asymmetric key-based JWT tokens
- **Argon2id Password Hashing** - Industry-standard password security
- **MFA (TOTP)** - Time-based one-time passwords with QR code setup
- **Rate Limiting** - Redis-backed Token Bucket algorithm with fail-closed for critical endpoints
- **Audit Logging** - Comprehensive security event logging
- **Anti-Bot Protection** - Honeypot fields in registration/login
- **Account Lockout** - Brute-force protection
- **Device Fingerprinting** - Session tracking and anti-hijacking
- **UUID v7** - Time-sortable UUIDs for all primary keys

## Technology Stack

- **Language:** Python 3.12+
- **Framework:** FastAPI (Async)
- **Database:** PostgreSQL 16 (AWS RDS)
- **ORM:** SQLAlchemy 2.0 (Async) + Alembic
- **Driver:** asyncpg
- **Rate Limiting:** Redis (Token Bucket)
- **Security:** JWT RS256, Argon2id, Fernet encryption

## Quick Start

### Prerequisites

- Python 3.12+
- PostgreSQL 16
- Redis 7+
- Docker & Docker Compose (optional)

### Local Development

1. **Clone and setup:**
   ```bash
   cd auth-python
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Generate JWT keys:**
   ```bash
   openssl genrsa -out private_key.pem 2048
   openssl rsa -in private_key.pem -pubout -out public_key.pem
   # Add keys to .env file
   ```

4. **Generate Fernet key:**
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   # Add to .env as FERNET_KEY
   ```

5. **Run database migrations:**
   ```bash
   alembic upgrade head
   ```

6. **Start the service:**
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

### Docker Compose

1. **Start all services:**
   ```bash
   docker-compose up -d
   ```

2. **Run migrations:**
   ```bash
   docker-compose exec auth-service alembic upgrade head
   ```

3. **Access the service:**
   - API: http://localhost:8000
   - Docs: http://localhost:8000/docs (if DEBUG=true)

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login (returns PRE_AUTH if MFA enabled)
- `POST /api/auth/verify-mfa` - Verify MFA code
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout and revoke session
- `POST /api/auth/change-password` - Change password (requires auth)
- `GET /api/auth/me` - Get current user info (requires auth)

### MFA

- `POST /api/auth/mfa/enable` - Generate MFA setup QR code
- `POST /api/auth/mfa/verify` - Verify and enable MFA
- `POST /api/auth/mfa/disable` - Disable MFA

### Health

- `GET /health` - Basic health check
- `GET /health/live` - Liveness check
- `GET /health/ready` - Readiness check (DB + Redis)

## Security Features

### Rate Limiting

- **Token Bucket Algorithm** - Redis-backed rate limiting
- **Fail-Closed** - Critical endpoints (`/login`, `/verify-mfa`) fail if Redis is unavailable
- **Per-IP Tracking** - Rate limits applied per client IP
- **Configurable Limits** - Different limits per endpoint

### Honeypot Protection

- Hidden `website_url` field in registration/login forms
- Bots that fill this field are silently rejected
- Logged as SUSPICIOUS_ACTIVITY

### Account Security

- **Account Lockout** - After 5 failed login attempts
- **Security Stamp** - UUID v7 that changes on password change/login/logout
- **Session Management** - Device fingerprinting and session revocation
- **Audit Logging** - All security events logged with risk scores

## Environment Variables

See `.env.example` for all required environment variables.

### Critical Variables

- `DATABASE_URL` - PostgreSQL connection string (must use `asyncpg` driver)
- `REDIS_URL` - Redis connection URL
- `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` - RS256 key pair
- `FERNET_KEY` - Fernet encryption key for MFA secrets

### AWS SSM Integration

Set `AWS_SSM_ENABLED=true` to load secrets from AWS SSM Parameter Store:
- `/auth-service/jwt/private-key`
- `/auth-service/jwt/public-key`
- `/auth-service/encryption/fernet-key`

## Database Migrations

```bash
# Create new migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Production Deployment

### AWS Considerations

- **t3.micro** - Database pool configured conservatively (pool_size=10, max_overflow=5)
- **Load Balancer** - IP extraction from `X-Forwarded-For` header
- **RDS** - PostgreSQL 16 on AWS RDS
- **ElastiCache** - Redis for rate limiting

### Security Checklist

- [ ] Change all default passwords
- [ ] Generate strong JWT keys (2048-bit RSA)
- [ ] Generate Fernet key
- [ ] Configure AWS SSM for secrets
- [ ] Set `DEBUG=false` in production
- [ ] Configure CORS origins
- [ ] Enable HTTPS/TLS
- [ ] Set up monitoring and alerting
- [ ] Configure log aggregation
- [ ] Review rate limiting thresholds

## Architecture

```
app/
├── core/              # Core configuration and security utilities
├── domain/            # Domain schemas (Pydantic models)
├── infrastructure/    # Database, Redis, external services
│   ├── database/     # SQLAlchemy models, repositories, connection
│   └── redis/        # Redis connection
├── application/       # Use cases and services
│   ├── services/     # MFA, audit, rate limiting services
│   └── use_cases/    # Business logic (register, login, etc.)
└── api/              # FastAPI routes, middleware, dependencies
    ├── routes/       # API endpoints
    └── middleware/   # Rate limiting, security headers
```

## License

Proprietary - Enterprise Security Grade

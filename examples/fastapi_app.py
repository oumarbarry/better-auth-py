"""Runnable better-auth-py demo.

    cd better-auth-py
    uv run uvicorn examples.fastapi_app:app --reload

Then:
    curl -s localhost:8000/api/auth/ok
    curl -s -c /tmp/jar -X POST localhost:8000/api/auth/sign-up/email \
        -H 'content-type: application/json' \
        -d '{"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"}'
    curl -s -b /tmp/jar localhost:8000/me

Optional GitHub login: export GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET and open
http://localhost:8000/api/auth/sign-in/social (POST {"provider": "github"}).
"""

import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.ext.asyncio import create_async_engine

from better_auth import BetterAuth, EmailAndPassword, EmailVerification, GitHub
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from better_auth.integrations.fastapi import BetterAuthFastAPI


async def print_email(user: dict, url: str, token: str) -> None:
    print(f"\n>> email to {user['email']}: {url}\n")  # plug your real mailer here


adapter = SQLAlchemyAdapter(create_async_engine("sqlite+aiosqlite:///./better-auth-demo.db"))

social_providers = {}
if os.environ.get("GITHUB_CLIENT_ID"):
    social_providers["github"] = GitHub(
        client_id=os.environ["GITHUB_CLIENT_ID"],
        client_secret=os.environ["GITHUB_CLIENT_SECRET"],
    )

auth = BetterAuth(
    secret=os.environ.get("BETTER_AUTH_SECRET", "dev-only-secret-please-change-me-1234"),
    base_url=os.environ.get("BETTER_AUTH_URL", "http://localhost:8000"),
    adapter=adapter,
    email_and_password=EmailAndPassword(enabled=True, send_reset_password=print_email),
    email_verification=EmailVerification(send_verification_email=print_email),
    social_providers=social_providers,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await adapter.create_tables()  # dev convenience; use real migrations in production
    yield


app = FastAPI(title="better-auth-py demo", lifespan=lifespan)
integration = BetterAuthFastAPI(auth)
app.include_router(integration.router)


@app.get("/me")
async def me(result: dict = Depends(integration.require_session)):
    return result["user"]


@app.get("/")
async def home(result: dict | None = Depends(integration.session)):
    return {"authenticated": result is not None}

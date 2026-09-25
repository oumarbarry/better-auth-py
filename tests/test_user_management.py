"""Tests for the account/session management endpoints added for TS parity:
/change-email, /delete-user, /delete-user/callback, /account-info, /update-session,
plus the change-email branch of /verify-email.
"""

from datetime import timedelta

from better_auth import EmailAndPassword, EmailVerification, Field
from better_auth.adapters.base import Where
from better_auth.config import (
    ChangeEmailOptions,
    DeleteUserOptions,
    SessionOptions,
    UserOptions,
)
from better_auth.oauth import OAuthProvider, OAuthUserInfo
from better_auth.session import utcnow
from conftest import SIGNUP, make_auth, make_client, sign_up

NEW_EMAIL = "grace@example.com"


# --- /update-session ------------------------------------------------------------------


async def test_update_session_writes_configured_field():
    # a configured additional session field with input allowed is written + emitted
    auth = make_auth(session=SessionOptions(additional_fields={"role": Field("string")}))
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/update-session", json={"role": "admin"})
        assert response.status_code == 200, response.text
        assert response.json()["session"]["role"] == "admin"


async def test_update_session_unconfigured_field_dropped():
    # nothing configured -> the schema-driven allowlist drops "role" -> empty write -> 400
    async with make_client(make_auth()) as client:
        await sign_up(client)
        response = await client.post("/api/auth/update-session", json={"role": "admin"})
        assert response.status_code == 400
        assert response.json()["message"] == "No fields to update"


async def test_update_session_core_field_dropped():
    async with make_client(make_auth()) as client:
        await sign_up(client)
        # a core-managed field is never in the input schema -> nothing updatable
        response = await client.post("/api/auth/update-session", json={"token": "nope"})
        assert response.status_code == 400
        assert response.json()["message"] == "No fields to update"


async def test_update_session_input_false_field_rejected():
    # a configured field with input=False cannot be set by a client (TS FIELD_NOT_ALLOWED)
    auth = make_auth(
        session=SessionOptions(additional_fields={"role": Field("string", input=False)})
    )
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/update-session", json={"role": "admin"})
        assert response.status_code == 400
        assert response.json()["code"] == "FIELD_NOT_ALLOWED"


async def test_update_session_requires_auth():
    async with make_client(make_auth()) as client:
        response = await client.post("/api/auth/update-session", json={"role": "admin"})
        assert response.status_code == 401


# --- /change-email --------------------------------------------------------------------


def change_email_auth(**change_email_opts):
    sent: list[tuple] = []

    async def send_verification_email(user, url, token):
        sent.append(("verify", user, url, token))

    async def send_confirmation(user, new_email, url, token):
        sent.append(("confirm", user, new_email, url, token))

    auth = make_auth(
        email_and_password=EmailAndPassword(enabled=True),
        email_verification=EmailVerification(send_verification_email=send_verification_email),
    )
    auth.user = UserOptions(
        change_email=ChangeEmailOptions(
            enabled=True, send_change_email_confirmation=send_confirmation, **change_email_opts
        )
    )
    return auth, sent


async def test_change_email_disabled():
    auth = make_auth()
    auth.user = UserOptions(change_email=ChangeEmailOptions(enabled=False))
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/change-email", json={"newEmail": NEW_EMAIL})
        assert response.status_code == 400
        assert response.json()["code"] == "CHANGE_EMAIL_DISABLED"


async def test_change_email_same_email():
    auth, _sent = change_email_auth(update_email_without_verification=True)
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/change-email", json={"newEmail": SIGNUP["email"]})
        assert response.status_code == 400
        assert response.json()["message"] == "Email is the same"


async def test_change_email_immediate_when_unverified():
    auth, sent = change_email_auth(update_email_without_verification=True)
    async with make_client(auth) as client:
        await sign_up(client)  # user is unverified
        response = await client.post("/api/auth/change-email", json={"newEmail": NEW_EMAIL})
        assert response.status_code == 200
        assert response.json() == {"status": True}
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["email"] == NEW_EMAIL
        # a verification email for the new address is also dispatched
        assert sent and sent[-1][0] == "verify"


async def test_change_email_existing_target_is_silent():
    auth, sent = change_email_auth(update_email_without_verification=True)
    async with make_client(auth) as client:
        await sign_up(client)
        # register a second user who already owns the target email
        await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Other", "email": NEW_EMAIL, "password": "another-pass"},
        )
        # re-auth as the first user (the second sign-up replaced the session cookie)
        await client.post("/api/auth/sign-in/email", json=SIGNUP)
        before = len(sent)
        response = await client.post("/api/auth/change-email", json={"newEmail": NEW_EMAIL})
        assert response.status_code == 200
        assert response.json() == {"status": True}
        # no email dispatched and the original email is unchanged (anti-enumeration no-op)
        assert len(sent) == before
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["email"] == SIGNUP["email"]


async def test_change_email_confirmation_handshake():
    auth, sent = change_email_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        # mark the user verified so the confirmation flow (not immediate update) is used
        await auth.adapter.update(
            "user", [Where("id", data["user"]["id"])], {"emailVerified": True}
        )

        response = await client.post("/api/auth/change-email", json={"newEmail": NEW_EMAIL})
        assert response.status_code == 200
        assert sent[-1][0] == "confirm"
        confirm_token = sent[-1][4]

        # step 1: click the confirmation link -> emails the new address a verification token
        step1 = await client.get(f"/api/auth/verify-email?token={confirm_token}")
        assert step1.status_code == 200
        assert step1.json() == {"status": True}
        assert sent[-1][0] == "verify"
        verify_token = sent[-1][3]

        # step 2: click the verification link -> email is updated and stays verified
        step2 = await client.get(f"/api/auth/verify-email?token={verify_token}")
        assert step2.status_code == 200
        assert step2.json()["user"]["email"] == NEW_EMAIL
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["email"] == NEW_EMAIL
        assert session["user"]["emailVerified"] is True


async def test_verify_email_change_wrong_session_user():
    auth, sent = change_email_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        await auth.adapter.update(
            "user", [Where("id", data["user"]["id"])], {"emailVerified": True}
        )
        await client.post("/api/auth/change-email", json={"newEmail": NEW_EMAIL})
        confirm_token = sent[-1][4]
        # sign out so the token is opened with a different (absent) session user...
        await client.post("/api/auth/sign-out")

        # a second user whose session does NOT match the token's `email`
        await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Mallory", "email": "mallory@example.com", "password": "mallory-pass"},
        )
        response = await client.get(f"/api/auth/verify-email?token={confirm_token}")
        assert response.status_code == 401
        assert response.json()["code"] == "INVALID_USER"


# --- /delete-user + /delete-user/callback ---------------------------------------------


def delete_user_auth(**delete_opts):
    events: list[tuple] = []

    async def before_delete(user, request):
        events.append(("before", user["id"]))

    async def after_delete(user, request):
        events.append(("after", user["id"]))

    auth = make_auth()
    auth.user = UserOptions(
        delete_user=DeleteUserOptions(
            enabled=True, before_delete=before_delete, after_delete=after_delete, **delete_opts
        )
    )
    return auth, events


async def test_delete_user_disabled_is_404():
    auth = make_auth()
    auth.user = UserOptions(delete_user=DeleteUserOptions(enabled=False))
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/delete-user", json={})
        assert response.status_code == 404


async def test_delete_user_fresh_session():
    auth, events = delete_user_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)  # fresh session
        response = await client.post("/api/auth/delete-user", json={})
        assert response.status_code == 200
        assert response.json() == {"success": True, "message": "User deleted"}
        assert events == [("before", data["user"]["id"]), ("after", data["user"]["id"])]
        # session cleared, user gone
        assert (await client.get("/api/auth/get-session")).json() is None
        assert await auth.adapter.find_one("user", [Where("id", data["user"]["id"])]) is None


async def test_delete_user_stale_session_requires_freshness():
    auth, _events = delete_user_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        token = (await client.get("/api/auth/get-session")).json()["session"]["token"]
        await auth.adapter.update(
            "session", [Where("token", token)], {"createdAt": utcnow() - timedelta(days=2)}
        )
        response = await client.post("/api/auth/delete-user", json={})
        assert response.status_code == 400
        assert response.json()["code"] == "SESSION_EXPIRED"


async def test_delete_user_with_password():
    auth, _events = delete_user_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        token = (await client.get("/api/auth/get-session")).json()["session"]["token"]
        # stale session, but a correct password authorizes deletion anyway
        await auth.adapter.update(
            "session", [Where("token", token)], {"createdAt": utcnow() - timedelta(days=2)}
        )
        wrong = await client.post("/api/auth/delete-user", json={"password": "not-the-password"})
        assert wrong.status_code == 400
        assert wrong.json()["code"] == "INVALID_PASSWORD"

        response = await client.post("/api/auth/delete-user", json={"password": SIGNUP["password"]})
        assert response.status_code == 200
        assert await auth.adapter.find_one("user", [Where("id", data["user"]["id"])]) is None


async def test_delete_user_verification_email_and_callback():
    sent: list[tuple] = []

    async def send_delete(user, url, token):
        sent.append((user, url, token))

    auth, _events = delete_user_auth(send_delete_account_verification=send_delete)
    async with make_client(auth) as client:
        data = await sign_up(client)
        response = await client.post("/api/auth/delete-user", json={})
        assert response.status_code == 200
        assert response.json() == {"success": True, "message": "Verification email sent"}
        # not deleted yet
        assert await auth.adapter.find_one("user", [Where("id", data["user"]["id"])]) is not None

        token = sent[0][2]
        callback = await client.get(f"/api/auth/delete-user/callback?token={token}")
        assert callback.status_code == 200
        assert callback.json() == {"success": True, "message": "User deleted"}
        assert await auth.adapter.find_one("user", [Where("id", data["user"]["id"])]) is None
        # accounts are cascaded on the callback path
        assert await auth.adapter.find_many("account", [Where("userId", data["user"]["id"])]) == []


async def test_delete_user_callback_rejects_foreign_token():
    sent: list[tuple] = []

    async def send_delete(user, url, token):
        sent.append((user, url, token))

    auth, _events = delete_user_auth(send_delete_account_verification=send_delete)
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/delete-user", json={})
        response = await client.get("/api/auth/delete-user/callback?token=not-a-real-token")
        assert response.status_code == 404
        assert response.json()["code"] == "INVALID_TOKEN"


async def test_delete_user_callback_rejects_expired_token():
    # TS 1.6.29 update-user.ts:639 consumeVerificationValue returns null past expiresAt.
    sent: list[tuple] = []

    async def send_delete(user, url, token):
        sent.append((user, url, token))

    auth, events = delete_user_auth(send_delete_account_verification=send_delete)
    async with make_client(auth) as client:
        data = await sign_up(client)
        await client.post("/api/auth/delete-user", json={})
        await auth.adapter.update_many(
            "verification", [], {"expiresAt": utcnow() - timedelta(seconds=1)}
        )
        response = await client.get(f"/api/auth/delete-user/callback?token={sent[0][2]}")
        assert response.status_code == 404
        assert response.json()["code"] == "INVALID_TOKEN"
        assert await auth.adapter.find_one("user", [Where("id", data["user"]["id"])]) is not None
        assert events == []


# --- /account-info --------------------------------------------------------------------


class FakeProvider(OAuthProvider):
    async def fetch_user(self, tokens, http):
        return OAuthUserInfo(
            id="ext-1", email="ext@example.com", name="Ext User", email_verified=True
        )


def account_info_auth():
    return make_auth(
        social_providers={"fake": FakeProvider(client_id="cid", client_secret="secret")}
    )


async def _link_account(auth, user_id, *, provider_id="fake", account_id="ext-1", **extra):
    now = utcnow()
    return await auth.adapter.create(
        "account",
        {
            "accountId": account_id,
            "providerId": provider_id,
            "userId": user_id,
            "createdAt": now,
            "updatedAt": now,
            **extra,
        },
    )


async def test_account_info_returns_provider_shape():
    # account.ts:1015-1063 (v1.7.6): selected by the Better Auth account id, and the
    # response names the account it read
    auth = account_info_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"], accessToken="at-123")
        response = await client.get(f"/api/auth/account-info?accountId={row['id']}")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["user"]["email"] == "ext@example.com"
        assert body["user"]["emailVerified"] is True
        assert body["data"] == {}
        assert body["account"] == {"id": row["id"], "providerId": "fake", "accountId": "ext-1"}


async def test_account_info_does_not_select_by_provider_account_id():
    auth = account_info_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        await _link_account(auth, data["user"]["id"], accessToken="at-123")
        response = await client.get("/api/auth/account-info?accountId=ext-1")
        assert response.status_code == 400
        assert response.json()["code"] == "ACCOUNT_NOT_FOUND"


async def test_account_info_rejects_the_legacy_provider_selection():
    # accountSelectionSchema is a strict object: providerId is no longer accepted
    auth = account_info_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"], accessToken="at-123")
        response = await client.get(f"/api/auth/account-info?accountId={row['id']}&providerId=fake")
        assert response.status_code == 400
        assert response.json()["code"] == "INVALID_BODY"


async def test_account_info_use_account_cookie_without_cookie_store():
    auth = account_info_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get("/api/auth/account-info?useAccountCookie=true")
        assert response.status_code == 400
        assert response.json()["code"] == "ACCOUNT_NOT_FOUND"


async def test_account_info_requires_auth():
    auth = account_info_auth()
    async with make_client(auth) as client:
        response = await client.get("/api/auth/account-info?accountId=ext-1")
        assert response.status_code == 401


async def test_account_info_unknown_account():
    auth = account_info_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get("/api/auth/account-info?accountId=missing")
        assert response.status_code == 400
        assert response.json()["code"] == "ACCOUNT_NOT_FOUND"


async def test_account_info_provider_not_configured():
    auth = account_info_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(
            auth, data["user"]["id"], provider_id="ghost", account_id="ext-9", accessToken="x"
        )
        response = await client.get(f"/api/auth/account-info?accountId={row['id']}")
        assert response.status_code == 400
        assert response.json()["code"] == "PROVIDER_NOT_CONFIGURED"


async def test_account_info_access_token_missing():
    auth = account_info_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"], account_id="ext-3")
        response = await client.get(f"/api/auth/account-info?accountId={row['id']}")
        assert response.status_code == 400
        assert response.json()["code"] == "ACCESS_TOKEN_NOT_FOUND"


async def test_account_info_is_scoped_to_the_session_user():
    auth = account_info_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        row = await _link_account(auth, "someone-else", accessToken="a")
        response = await client.get(f"/api/auth/account-info?accountId={row['id']}")
        assert response.status_code == 400
        assert response.json()["code"] == "ACCOUNT_NOT_FOUND"


# --- /unlink-account (account.ts:453-509, v1.7.6) -------------------------------------


async def test_unlink_account_by_account_id():
    auth = account_info_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"])
        response = await client.post("/api/auth/unlink-account", json={"accountId": row["id"]})
        assert response.json() == {"status": True}
    assert await auth.adapter.find_one("account", [Where("id", row["id"])]) is None


async def test_unlink_account_needs_the_account_id():
    auth = account_info_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        await _link_account(auth, data["user"]["id"])
        response = await client.post("/api/auth/unlink-account", json={"providerId": "fake"})
        assert response.status_code == 400
        assert response.json()["code"] == "INVALID_BODY"


async def test_unlink_last_account_refused_before_lookup():
    auth = account_info_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/unlink-account", json={"accountId": "nope"})
        assert response.status_code == 400
        assert response.json()["code"] == "FAILED_TO_UNLINK_LAST_ACCOUNT"


async def test_unlink_account_requires_a_fresh_session():
    auth = make_auth(
        social_providers={"fake": FakeProvider(client_id="cid", client_secret="secret")},
        session=SessionOptions(fresh_age=60),
    )
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"])
        await auth.adapter.update(
            "session",
            [Where("userId", data["user"]["id"])],
            {"createdAt": utcnow() - timedelta(seconds=120)},
        )
        response = await client.post("/api/auth/unlink-account", json={"accountId": row["id"]})
        assert response.status_code == 403
        assert response.json() == {"code": "SESSION_NOT_FRESH", "message": "Session is not fresh"}


# --- legacy change-email token (externally minted, no requestType) --------------------


async def test_verify_email_legacy_update_branch():
    """A JWT carrying updateTo but no requestType updates the email immediately and
    leaves it unverified (email-verification.ts legacy `default` branch)."""
    from better_auth.crypto import sign_email_verification_token

    auth, _sent = change_email_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        await auth.adapter.update(
            "user", [Where("id", data["user"]["id"])], {"emailVerified": True}
        )
        token = sign_email_verification_token(auth.secret, SIGNUP["email"], update_to=NEW_EMAIL)
        response = await client.get(f"/api/auth/verify-email?token={token}")
        assert response.status_code == 200
        assert response.json()["user"]["email"] == NEW_EMAIL
        assert response.json()["user"]["emailVerified"] is False


# --- AccountOptions.legacy_account_selection (port-only, deprecated) -------------------


def _legacy_auth(enabled: bool):
    from better_auth.config import AccountOptions

    return make_auth(
        social_providers={"fake": FakeProvider(client_id="cid", client_secret="secret")},
        account=AccountOptions(legacy_account_selection=enabled),
    )


async def test_legacy_unlink_by_provider_when_opted_in():
    auth = _legacy_auth(True)
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"])
        response = await client.post(
            "/api/auth/unlink-account", json={"providerId": "fake", "accountId": "ext-1"}
        )
        assert response.json() == {"status": True}
    assert await auth.adapter.find_one("account", [Where("id", row["id"])]) is None


async def test_legacy_unlink_keeps_the_last_account_rule():
    auth = _legacy_auth(True)
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/unlink-account", json={"providerId": "credential"})
    assert response.json()["code"] == "FAILED_TO_UNLINK_LAST_ACCOUNT"


async def test_legacy_unlink_still_accepts_the_row_id():
    auth = _legacy_auth(True)
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"])
        response = await client.post("/api/auth/unlink-account", json={"accountId": row["id"]})
    assert response.json() == {"status": True}


async def test_legacy_unlink_body_refused_by_default():
    auth = _legacy_auth(False)
    async with make_client(auth) as client:
        data = await sign_up(client)
        await _link_account(auth, data["user"]["id"])
        response = await client.post("/api/auth/unlink-account", json={"providerId": "fake"})
    assert response.status_code == 400 and response.json()["code"] == "INVALID_BODY"


async def test_legacy_account_info_by_provider_account_id():
    auth = _legacy_auth(True)
    async with make_client(auth) as client:
        data = await sign_up(client)
        row = await _link_account(auth, data["user"]["id"], accessToken="at-1")
        by_pair = await client.get("/api/auth/account-info?accountId=ext-1&providerId=fake")
        by_provider_id = await client.get("/api/auth/account-info?accountId=ext-1")
        by_row = await client.get(f"/api/auth/account-info?accountId={row['id']}")
    for response in (by_pair, by_provider_id, by_row):
        assert response.status_code == 200, response.text
        assert response.json()["account"]["id"] == row["id"]


async def test_legacy_account_info_ambiguous_provider_account_id():
    from better_auth.config import AccountOptions

    auth = make_auth(
        social_providers={
            "fake": FakeProvider(client_id="cid", client_secret="secret"),
            "other": FakeProvider(client_id="cid2", client_secret="secret2"),
        },
        account=AccountOptions(legacy_account_selection=True),
    )
    async with make_client(auth) as client:
        data = await sign_up(client)
        await _link_account(auth, data["user"]["id"], account_id="dup", accessToken="a")
        await _link_account(
            auth, data["user"]["id"], provider_id="other", account_id="dup", accessToken="b"
        )
        response = await client.get("/api/auth/account-info?accountId=dup")
    assert response.json()["code"] == "AMBIGUOUS_ACCOUNT"

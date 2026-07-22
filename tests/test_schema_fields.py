"""Field-attribute model parity (item 1) and parse-layer functions (item 3)."""

from __future__ import annotations

from better_auth.schema import (
    CORE_SCHEMA,
    Field,
    Reference,
    filter_output_fields,
    parse_account_output,
)


def test_field_has_parity_attributes():
    f = Field(
        "string",
        required=True,
        unique=True,
        returned=False,
        input=False,
        sortable=True,
        index=True,
        bigint=True,
        field_name="col",
    )
    assert f.returned is False
    assert f.input is False
    assert f.sortable is True
    assert f.index is True
    assert f.bigint is True
    assert f.field_name == "col"


def test_email_verified_default_false():
    f = CORE_SCHEMA["user"]["emailVerified"]
    assert f.default is False
    assert f.input is False


def test_updated_at_has_on_update():
    assert CORE_SCHEMA["user"]["updatedAt"].on_update is not None
    assert CORE_SCHEMA["user"]["createdAt"].on_update is None


def test_structured_references_with_on_delete():
    ref = CORE_SCHEMA["session"]["userId"].references
    assert isinstance(ref, Reference)
    assert ref.model == "user"
    assert ref.field == "id"
    assert ref.on_delete == "cascade"


def test_account_tokens_marked_not_returned():
    for field in ("accessToken", "refreshToken", "idToken", "password"):
        assert CORE_SCHEMA["account"][field].returned is False


def test_filter_output_fields_strips_not_returned():
    row = {"id": "1", "email": "a@b.com", "password": "secret"}
    out = filter_output_fields(row, CORE_SCHEMA["account"])
    assert "password" not in out
    assert "email" in out


def test_parse_account_output_strips_sensitive():
    account = {
        "id": "1",
        "accountId": "x",
        "providerId": "credential",
        "accessToken": "tok",
        "password": "hash",
        "scope": "email",
    }
    out = parse_account_output(account)
    assert "accessToken" not in out
    assert "password" not in out
    assert out["scope"] == "email"

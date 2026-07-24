"""oauth-provider database schema — 4 tables, exact camelCase columns.

Port of TS ``packages/oauth-provider/src/schema.ts`` (v1.6.23). Column names match the TS
provider exactly so a DB written by the TS provider is readable by the Python port. All 4
tables are defined now (Phase A uses only ``oauthClient``/``oauthConsent``) so the schema is
complete for cross-runtime compatibility.
"""

from __future__ import annotations

from ...schema import Field, Reference, Schema

OAUTH_PROVIDER_SCHEMA: Schema = {
    "oauthClient": {
        # Important fields
        "clientId": Field("string", unique=True, required=True),
        "clientSecret": Field("string", required=False, returned=False),
        "disabled": Field("boolean", required=False, default=False),
        "skipConsent": Field("boolean", required=False),
        "enableEndSession": Field("boolean", required=False),
        "subjectType": Field("string", required=False),
        "scopes": Field("string[]", required=False),
        # Recommended client data
        "userId": Field("string", required=False, references=Reference("user", "id"), index=True),
        "createdAt": Field("datetime", required=False),
        "updatedAt": Field("datetime", required=False),
        # UI metadata
        "name": Field("string", required=False),
        "uri": Field("string", required=False),
        "icon": Field("string", required=False),
        "contacts": Field("string[]", required=False),
        "tos": Field("string", required=False),
        "policy": Field("string", required=False),
        # Software identifiers
        "softwareId": Field("string", required=False),
        "softwareVersion": Field("string", required=False),
        "softwareStatement": Field("string", required=False),
        # Authentication metadata
        "redirectUris": Field("string[]", required=True),
        "postLogoutRedirectUris": Field("string[]", required=False),
        "tokenEndpointAuthMethod": Field("string", required=False),
        "grantTypes": Field("string[]", required=False),
        "responseTypes": Field("string[]", required=False),
        # RFC6749
        "public": Field("boolean", required=False),
        "type": Field("string", required=False),
        "requirePKCE": Field("boolean", required=False),
        # Other
        "referenceId": Field("string", required=False),
        "metadata": Field("json", required=False),
    },
    "oauthConsent": {
        "clientId": Field(
            "string", required=True, references=Reference("oauthClient", "clientId"), index=True
        ),
        "userId": Field("string", required=False, references=Reference("user", "id"), index=True),
        "referenceId": Field("string", required=False),
        "scopes": Field("string[]", required=True),
        "createdAt": Field("datetime", required=False),
        "updatedAt": Field("datetime", required=False),
    },
    # An opaque refresh token created with "offline_access" (linked to a session).
    "oauthRefreshToken": {
        "token": Field("string", required=True, unique=True),
        "clientId": Field(
            "string", required=True, references=Reference("oauthClient", "clientId"), index=True
        ),
        "sessionId": Field(
            "string",
            required=False,
            references=Reference("session", "id", on_delete="set null"),
            index=True,
        ),
        "userId": Field("string", required=True, references=Reference("user", "id"), index=True),
        "referenceId": Field("string", required=False),
        "expiresAt": Field("datetime", required=False),
        "createdAt": Field("datetime", required=False),
        "revoked": Field("datetime", required=False),
        "authTime": Field("datetime", required=False),
        "scopes": Field("string[]", required=True),  # immutable
    },
    # An opaque access token (created at issuance, destroyed at revoke, read at introspection;
    # never updated). Linked to a session — callers SHALL always check for a valid session.
    "oauthAccessToken": {
        "token": Field("string", unique=True),
        "clientId": Field(
            "string", required=True, references=Reference("oauthClient", "clientId"), index=True
        ),
        "sessionId": Field(
            "string",
            required=False,
            references=Reference("session", "id", on_delete="set null"),
            index=True,
        ),
        "userId": Field("string", required=False, references=Reference("user", "id"), index=True),
        "referenceId": Field("string", required=False),
        "refreshId": Field(
            "string", required=False, references=Reference("oauthRefreshToken", "id"), index=True
        ),
        "expiresAt": Field("datetime", required=False),
        "createdAt": Field("datetime", required=False),
        "scopes": Field("string[]", required=True),
    },
}

"""oauth-provider database schema: 7 tables, exact camelCase columns.

Port of TS ``packages/oauth-provider/src/schema.ts`` (v1.7.6). Column names match the TS
provider exactly so a DB written by the TS provider is readable by the Python port.
``oauthClient``/``oauthConsent`` back client management and consent,
``oauthAccessToken``/``oauthRefreshToken`` back the token, introspect, and revoke endpoints,
``oauthResource``/``oauthClientResource`` model protected resources, and
``oauthClientAssertion`` records single-use ``private_key_jwt`` ids.
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
        # Machine scopes for the client_credentials grant (TS schema.ts:42, 5c45abcd2).
        "clientCredentialsScopes": Field("string[]", required=False, default_factory=list),
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
        # RFC 8707 resources and OIDC claims.userinfo names bound to the grant (TS schema.ts).
        "resources": Field("string[]", required=False),
        "requestedUserInfoClaims": Field("string[]", required=False),
        "scopes": Field("string[]", required=True),
        "createdAt": Field("datetime", required=False),
        "updatedAt": Field("datetime", required=False),
    },
    # A protected resource the AS issues access tokens for (TS schema.ts oauthResource,
    # d2a79bae7). A null policy column inherits the plugin default at issuance time.
    "oauthResource": {
        "identifier": Field("string", required=True, unique=True),
        "name": Field("string", required=True),
        "accessTokenTtl": Field("number", required=False),
        "refreshTokenTtl": Field("number", required=False),
        "signingAlgorithm": Field("string", required=False),
        "signingKeyId": Field("string", required=False),
        "allowedScopes": Field("string[]", required=False),
        "customClaims": Field("json", required=False),
        "dpopBoundAccessTokensRequired": Field("boolean", required=False, default=False),
        "disabled": Field("boolean", required=False, default=False),
        "createdAt": Field("datetime", required=False),
        "updatedAt": Field("datetime", required=False),
        "policyVersion": Field("number", required=False, default=1),
        "metadata": Field("json", required=False),
    },
    # Which clients may request which resources (TS schema.ts oauthClientResource).
    # ponytail: the TS composite unique index on (clientId, resourceId) is not expressible in
    # this schema model; the link endpoint checks for an existing pair before inserting.
    "oauthClientResource": {
        "clientId": Field(
            "string",
            required=True,
            references=Reference("oauthClient", "clientId", on_delete="cascade"),
            index=True,
        ),
        "resourceId": Field(
            "string",
            required=True,
            references=Reference("oauthResource", "identifier", on_delete="cascade"),
            index=True,
        ),
        "metadata": Field("json", required=False),
        "createdAt": Field("datetime", required=False),
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
        # Hashed code the token family was issued for (TS schema.ts, 508d8d6f0).
        "authorizationCodeId": Field("string", required=False, index=True),
        "resources": Field("string[]", required=False),
        "requestedUserInfoClaims": Field("string[]", required=False),
        "expiresAt": Field("datetime", required=False),
        "createdAt": Field("datetime", required=False),
        "revoked": Field("datetime", required=False),
        # Rotation bookkeeping for refreshTokenReuseInterval (TS schema.ts, 5838df2f4).
        "rotatedAt": Field("datetime", required=False),
        "rotationReplayResponse": Field("string", required=False),
        "rotationReplayExpiresAt": Field("datetime", required=False),
        "authTime": Field("datetime", required=False),
        # RFC 7800 cnf sender constraint (DPoP {jkt}), carried forward on rotation.
        "confirmation": Field("json", required=False),
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
        "authorizationCodeId": Field("string", required=False, index=True),
        "resources": Field("string[]", required=False),
        "requestedUserInfoClaims": Field("string[]", required=False),
        "refreshId": Field(
            "string", required=False, references=Reference("oauthRefreshToken", "id"), index=True
        ),
        "expiresAt": Field("datetime", required=False),
        "createdAt": Field("datetime", required=False),
        # Set by back-channel logout as a stored backstop (TS schema.ts, e0d2b9eb9).
        "revoked": Field("datetime", required=False),
        # RFC 7800 cnf sender constraint (DPoP {jkt}), surfaced as cnf at introspection.
        "confirmation": Field("json", required=False),
        "scopes": Field("string[]", required=True),
    },
    # Single-use private_key_jwt assertion jti markers; the id is a digest of the namespaced jti,
    # so a replay collides on the primary key (TS schema.ts oauthClientAssertion, 7abaaed53).
    "oauthClientAssertion": {
        "expiresAt": Field("datetime", required=True),
    },
}

"""Endpoint catalog: one line per endpoint, both client shells are generated from it.

Each entry maps a dotted client path (``sign_in.email``) to ``(HTTP method, route)``.
GET entries send kwargs as query params, POST entries as the JSON body — kwargs are
passed verbatim as wire keys (camelCase where the wire is camelCase, snake_case where
it is snake_case, e.g. the OAuth-shaped device routes).

Sources of truth in the server package (nothing invented):
- core: ``better_auth/endpoints.py`` ROUTES (surface per the design spec);
- plugins: each ``Plugin.routes()`` in ``better_auth/plugins_ext/``.

A dotted path that is also a route of its own (``device`` for ``GET /device``,
``forget_password`` next to ``forget_password.email_otp``) becomes a *callable*
namespace.
"""

from __future__ import annotations

#: (dotted client path, HTTP method, route path) — max two levels deep.
CATALOG: tuple[tuple[str, str, str], ...] = (
    # --- core (endpoints.py ROUTES) ---------------------------------------------------
    ("sign_up.email", "POST", "/sign-up/email"),
    ("sign_in.email", "POST", "/sign-in/email"),
    ("sign_in.social", "POST", "/sign-in/social"),
    ("sign_out", "POST", "/sign-out"),
    ("get_session", "GET", "/get-session"),
    ("list_sessions", "GET", "/list-sessions"),
    ("revoke_session", "POST", "/revoke-session"),
    ("revoke_sessions", "POST", "/revoke-sessions"),
    ("revoke_other_sessions", "POST", "/revoke-other-sessions"),
    ("forget_password", "POST", "/forget-password"),
    ("reset_password", "POST", "/reset-password"),
    ("change_password", "POST", "/change-password"),
    ("set_password", "POST", "/set-password"),
    ("verify_email", "GET", "/verify-email"),
    ("send_verification_email", "POST", "/send-verification-email"),
    ("change_email", "POST", "/change-email"),
    ("update_user", "POST", "/update-user"),
    ("delete_user", "POST", "/delete-user"),
    ("list_accounts", "GET", "/list-accounts"),
    ("link_social", "POST", "/link-social"),
    ("unlink_account", "POST", "/unlink-account"),
    ("refresh_token", "POST", "/refresh-token"),
    ("get_access_token", "POST", "/get-access-token"),
    ("account_info", "GET", "/account-info"),
    # --- two-factor (plugins_ext/two_factor.py) ---------------------------------------
    ("two_factor.enable", "POST", "/two-factor/enable"),
    ("two_factor.disable", "POST", "/two-factor/disable"),
    ("two_factor.get_totp_uri", "POST", "/two-factor/get-totp-uri"),
    ("two_factor.verify_totp", "POST", "/two-factor/verify-totp"),
    ("two_factor.send_otp", "POST", "/two-factor/send-otp"),
    ("two_factor.verify_otp", "POST", "/two-factor/verify-otp"),
    ("two_factor.verify_backup_code", "POST", "/two-factor/verify-backup-code"),
    ("two_factor.generate_backup_codes", "POST", "/two-factor/generate-backup-codes"),
    # --- organization (plugins_ext/organization.py; teams/dynamic-AC routes exist
    #     server-side only when those options are enabled) -----------------------------
    ("organization.create", "POST", "/organization/create"),
    ("organization.update", "POST", "/organization/update"),
    ("organization.delete", "POST", "/organization/delete"),
    ("organization.set_active", "POST", "/organization/set-active"),
    ("organization.get_full_organization", "GET", "/organization/get-full-organization"),
    ("organization.list", "GET", "/organization/list"),
    ("organization.check_slug", "POST", "/organization/check-slug"),
    ("organization.leave", "POST", "/organization/leave"),
    ("organization.list_members", "GET", "/organization/list-members"),
    ("organization.remove_member", "POST", "/organization/remove-member"),
    ("organization.update_member_role", "POST", "/organization/update-member-role"),
    ("organization.get_active_member", "GET", "/organization/get-active-member"),
    ("organization.has_permission", "POST", "/organization/has-permission"),
    ("organization.invite_member", "POST", "/organization/invite-member"),
    ("organization.accept_invitation", "POST", "/organization/accept-invitation"),
    ("organization.reject_invitation", "POST", "/organization/reject-invitation"),
    ("organization.cancel_invitation", "POST", "/organization/cancel-invitation"),
    ("organization.get_invitation", "GET", "/organization/get-invitation"),
    ("organization.list_invitations", "GET", "/organization/list-invitations"),
    ("organization.list_user_invitations", "GET", "/organization/list-user-invitations"),
    ("organization.create_team", "POST", "/organization/create-team"),
    ("organization.update_team", "POST", "/organization/update-team"),
    ("organization.remove_team", "POST", "/organization/remove-team"),
    ("organization.list_teams", "GET", "/organization/list-teams"),
    ("organization.set_active_team", "POST", "/organization/set-active-team"),
    ("organization.list_user_teams", "GET", "/organization/list-user-teams"),
    ("organization.list_team_members", "GET", "/organization/list-team-members"),
    ("organization.add_team_member", "POST", "/organization/add-team-member"),
    ("organization.remove_team_member", "POST", "/organization/remove-team-member"),
    ("organization.create_role", "POST", "/organization/create-role"),
    ("organization.delete_role", "POST", "/organization/delete-role"),
    ("organization.list_roles", "GET", "/organization/list-roles"),
    ("organization.get_role", "GET", "/organization/get-role"),
    ("organization.update_role", "POST", "/organization/update-role"),
    # --- admin (plugins_ext/admin.py) -------------------------------------------------
    ("admin.set_role", "POST", "/admin/set-role"),
    ("admin.get_user", "GET", "/admin/get-user"),
    ("admin.create_user", "POST", "/admin/create-user"),
    ("admin.update_user", "POST", "/admin/update-user"),
    ("admin.list_users", "GET", "/admin/list-users"),
    ("admin.list_user_sessions", "POST", "/admin/list-user-sessions"),
    ("admin.ban_user", "POST", "/admin/ban-user"),
    ("admin.unban_user", "POST", "/admin/unban-user"),
    ("admin.impersonate_user", "POST", "/admin/impersonate-user"),
    ("admin.stop_impersonating", "POST", "/admin/stop-impersonating"),
    ("admin.revoke_user_session", "POST", "/admin/revoke-user-session"),
    ("admin.revoke_user_sessions", "POST", "/admin/revoke-user-sessions"),
    ("admin.remove_user", "POST", "/admin/remove-user"),
    ("admin.set_user_password", "POST", "/admin/set-user-password"),
    ("admin.has_permission", "POST", "/admin/has-permission"),
    # --- api-key (plugins_ext/api_key.py) ---------------------------------------------
    ("api_key.create", "POST", "/api-key/create"),
    ("api_key.get", "GET", "/api-key/get"),
    ("api_key.update", "POST", "/api-key/update"),
    ("api_key.delete", "POST", "/api-key/delete"),
    ("api_key.list", "GET", "/api-key/list"),
    # --- magic-link (plugins_ext/magic_link.py) ---------------------------------------
    ("sign_in.magic_link", "POST", "/sign-in/magic-link"),
    ("magic_link.verify", "GET", "/magic-link/verify"),
    # --- email-otp (plugins_ext/email_otp.py) -----------------------------------------
    ("email_otp.send_verification_otp", "POST", "/email-otp/send-verification-otp"),
    ("email_otp.check_verification_otp", "POST", "/email-otp/check-verification-otp"),
    ("email_otp.verify_email", "POST", "/email-otp/verify-email"),
    ("sign_in.email_otp", "POST", "/sign-in/email-otp"),
    ("email_otp.request_password_reset", "POST", "/email-otp/request-password-reset"),
    ("forget_password.email_otp", "POST", "/forget-password/email-otp"),
    ("email_otp.reset_password", "POST", "/email-otp/reset-password"),
    ("email_otp.request_email_change", "POST", "/email-otp/request-email-change"),
    ("email_otp.change_email", "POST", "/email-otp/change-email"),
    # --- device-authorization (plugins_ext/device_authorization.py) --------------------
    ("device", "GET", "/device"),
    ("device.code", "POST", "/device/code"),
    ("device.token", "POST", "/device/token"),
    ("device.approve", "POST", "/device/approve"),
    ("device.deny", "POST", "/device/deny"),
)

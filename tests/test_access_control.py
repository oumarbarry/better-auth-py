"""Access-control subsystem (gap item: access-control) — role authorization and the
admin/organization default statement/role tables. Pure logic, no HTTP.

Verified against better-auth TS:
- plugins/access/access.ts (createAccessControl, role, authorize)
- plugins/admin/access/statement.ts (admin defaults)
- plugins/organization/access/statement.ts (organization defaults)
"""

from __future__ import annotations

from typing import Any

import pytest

from better_auth.access_control import (
    ADMIN_DEFAULT_ROLES,
    ADMIN_DEFAULT_STATEMENTS,
    ORG_DEFAULT_ROLES,
    ORG_DEFAULT_STATEMENTS,
    AccessControl,
    AccessControlError,
    Role,
    create_access_control,
)

STATEMENTS = {
    "project": ["create", "update", "delete", "delete-many"],
    "ui": ["view", "edit", "comment", "hide"],
}


@pytest.fixture
def ac() -> AccessControl:
    return create_access_control(STATEMENTS)


@pytest.fixture
def role1(ac: AccessControl) -> Role:
    return ac.new_role(
        {
            "project": ["create", "update", "delete"],
            "ui": ["view", "edit", "comment"],
        }
    )


# --- createAccessControl / role construction ------------------------------------


def test_create_access_control_exposes_statements(ac: AccessControl):
    assert ac.statements is STATEMENTS


def test_new_role_exposes_its_own_statements(role1: Role):
    assert role1.statements == {
        "project": ["create", "update", "delete"],
        "ui": ["view", "edit", "comment"],
    }


def test_new_role_accepts_the_full_base_statements_directly(ac: AccessControl):
    role2 = ac.new_role(STATEMENTS)
    assert role2.authorize({"project": ["create"]}) == {"success": True}


def test_new_role_performs_no_runtime_subset_validation(ac: AccessControl):
    """TS enforces 'subset of base statements' only through RoleInput/Subset generics
    at compile time; newRole itself does zero runtime checking (just role(statements)).
    A role may declare actions/resources absent from the base statements and it is
    still constructed and independently authorizes against its own statements."""
    role2 = ac.new_role({"billing": ["read"], "project": ["publish"]})
    assert role2.statements == {"billing": ["read"], "project": ["publish"]}
    assert role2.authorize({"billing": ["read"]}) == {"success": True}
    assert role2.authorize({"project": ["publish"]}) == {"success": True}


def test_bare_role_function_is_equivalent_to_new_role():
    from better_auth.access_control import role as role_fn

    r = role_fn({"project": ["create"]})
    assert r.authorize({"project": ["create"]}) == {"success": True}


# --- basic AND/OR authorization ---------------------------------------------------


def test_validates_single_resource_permission(role1: Role):
    assert role1.authorize({"project": ["create"]}) == {"success": True}


def test_rejects_disallowed_action(role1: Role):
    response = role1.authorize({"project": ["delete-many"]})
    assert response["success"] is False


def test_validates_multiple_resource_permissions_success(role1: Role):
    response = role1.authorize({"project": ["create"], "ui": ["view"]})
    assert response == {"success": True}


def test_validates_multiple_resource_permissions_failure(role1: Role):
    response = role1.authorize({"project": ["delete-many"], "ui": ["view"]})
    assert response["success"] is False


def test_and_requires_every_action_in_a_resource_list(role1: Role):
    ok = role1.authorize({"project": ["create", "delete"], "ui": ["view", "edit"]})
    assert ok == {"success": True}

    fail = role1.authorize({"project": ["create", "delete-many"], "ui": ["view", "edit"]})
    assert fail["success"] is False


def test_top_level_or_succeeds_if_any_resource_is_authorized(role1: Role):
    response = role1.authorize(
        {"project": ["create", "delete-many"], "ui": ["view", "edit"]},
        "OR",
    )
    assert response == {"success": True}


def test_top_level_or_fails_when_no_resource_is_authorized(role1: Role):
    response = role1.authorize({"project": ["delete-many"], "ui": ["hide", "view"]}, "OR")
    # "ui" contains "hide" which role1 does not have (only view/edit/comment) so
    # under a per-resource AND (default), "ui" also fails -> nothing authorized.
    assert response == {"success": False, "error": "Not authorized"}


def test_top_level_or_short_circuits_on_first_authorized_resource(role1: Role):
    """OR must return as soon as the first resource authorizes, without evaluating
    later ones. Proven with a malformed later value ("ui": None) that would raise
    AccessControlError if it were ever normalized — its absence proves the loop
    returned before reaching it. (Deliberately-invalid input, like TS's own
    `as never` casts in access.test.ts — typed as Any to probe the runtime path
    without weakening authorize()'s real signature.)"""
    request: Any = {"project": ["create"], "ui": None}
    response = role1.authorize(request, "OR")
    assert response == {"success": True}


def test_and_short_circuits_on_first_unauthorized_resource(role1: Role):
    """AND must return as soon as the first resource fails, without evaluating later
    ones. Proven with a malformed later value ("ui": None) that would raise
    AccessControlError if it were ever normalized."""
    request: Any = {"project": ["delete-many"], "ui": None}
    response = role1.authorize(request)
    assert response == {
        "success": False,
        "error": 'unauthorized to access resource "project"',
    }


# --- per-resource connector (object form) -----------------------------------------


def test_per_resource_or_connector_any_action_suffices(role1: Role):
    response = role1.authorize(
        {
            "project": {"connector": "OR", "actions": ["create", "delete-many"]},
            "ui": ["view", "edit"],
        }
    )
    assert response == {"success": True}


def test_per_resource_or_connector_still_requires_other_resources(role1: Role):
    response = role1.authorize(
        {
            "project": {"connector": "OR", "actions": ["create", "delete-many"]},
            "ui": ["view", "edit", "hide"],
        }
    )
    assert response["success"] is False


def test_per_resource_and_connector_explicit_object_form(role1: Role):
    response = role1.authorize({"project": {"actions": ["create", "update"], "connector": "AND"}})
    assert response == {"success": True}

    failed = role1.authorize(
        {"project": {"actions": ["create", "delete-many"], "connector": "AND"}}
    )
    assert failed["success"] is False


def test_unknown_per_resource_connector_value_defaults_to_and(role1: Role):
    response = role1.authorize(
        {"project": {"actions": ["create", "delete-many"], "connector": "XOR"}}
    )
    assert response["success"] is False


# --- empty action lists -------------------------------------------------------------


def test_empty_action_list_array_form_is_not_authorized(role1: Role):
    assert role1.authorize({"project": []})["success"] is False
    assert role1.authorize({"project": []}, "OR")["success"] is False


def test_empty_action_list_object_form_is_not_authorized(role1: Role):
    assert role1.authorize({"project": {"actions": [], "connector": "AND"}})["success"] is False
    assert role1.authorize({"project": {"actions": [], "connector": "OR"}})["success"] is False


def test_or_across_resources_fails_when_every_resource_is_empty(role1: Role):
    response = role1.authorize({"project": [], "ui": []}, "OR")
    assert response["success"] is False


# --- unknown resource ---------------------------------------------------------------


def test_unknown_resource_fails_under_and(role1: Role):
    response = role1.authorize({"billing": ["read"]})
    assert response == {
        "success": False,
        "error": "You are not allowed to access resource: billing",
    }


def test_unknown_resource_is_skipped_under_or_and_later_resource_wins(role1: Role):
    response = role1.authorize({"billing": ["read"], "project": ["create"]}, "OR")
    assert response == {"success": True}


def test_unknown_resource_under_or_with_nothing_else_authorized_fails_not_authorized(role1: Role):
    response = role1.authorize({"billing": ["read"], "project": ["delete-many"]}, "OR")
    assert response == {"success": False, "error": "Not authorized"}


def test_and_fails_on_first_unknown_resource_even_with_valid_ones_present(role1: Role):
    response = role1.authorize({"billing": ["read"], "project": ["create"]})
    assert response["success"] is False
    assert "billing" in response["error"]


def test_present_but_empty_allowed_actions_is_unauthorized_not_unknown():
    """A resource key that *exists* in the role's statements with an empty allowed-
    actions list (e.g. org member role's `organization: []`) must NOT be treated the
    same as an absent/unknown resource key, even though both `[]` and "missing" are
    falsy in Python — JS `![]` is `false` (arrays are always truthy in JS), so TS only
    takes the unknown-resource branch when the key is actually absent."""
    ac = create_access_control({"organization": ["update", "delete"]})
    member = ac.new_role({"organization": []})

    response = member.authorize({"organization": ["update"]})
    assert response == {
        "success": False,
        "error": 'unauthorized to access resource "organization"',
    }


# --- exact error message formats ----------------------------------------------------


def test_exact_unknown_resource_error_format(role1: Role):
    response = role1.authorize({"billing": ["read"]})
    assert response == {
        "success": False,
        "error": "You are not allowed to access resource: billing",
    }


def test_exact_unauthorized_resource_error_format(role1: Role):
    response = role1.authorize({"project": ["delete-many"]})
    assert response == {
        "success": False,
        "error": 'unauthorized to access resource "project"',
    }


def test_exact_not_authorized_error_format(role1: Role):
    response = role1.authorize({"project": [], "ui": []}, "OR")
    assert response == {"success": False, "error": "Not authorized"}


def test_successful_response_has_no_error_key(role1: Role):
    response = role1.authorize({"project": ["create"]})
    assert response == {"success": True}
    assert "error" not in response


# --- non-string action values / malformed requests -----------------------------------


def test_non_string_action_values_are_unauthorized_not_crashing(role1: Role):
    request: Any = {"project": ["create", 1]}
    response = role1.authorize(request)
    assert response == {
        "success": False,
        "error": 'unauthorized to access resource "project"',
    }


@pytest.mark.parametrize("bad_value", [None, "read", 42, True, 3.14])
def test_invalid_per_resource_request_value_raises(role1: Role, bad_value):
    with pytest.raises(AccessControlError):
        role1.authorize({"project": bad_value})


def test_object_form_with_non_list_actions_does_not_raise_and_is_unauthorized(role1: Role):
    response = role1.authorize({"project": {"actions": "create"}})
    assert response["success"] is False


# --- admin default tables (plugins/admin/access/statement.ts) ------------------------


def test_admin_default_statements_exact():
    assert ADMIN_DEFAULT_STATEMENTS == {
        "user": [
            "create",
            "list",
            "set-role",
            "ban",
            "impersonate",
            "impersonate-admins",
            "delete",
            "set-password",
            "set-email",
            "get",
            "update",
        ],
        "session": ["list", "revoke", "delete"],
    }


def test_admin_default_roles_keys():
    assert set(ADMIN_DEFAULT_ROLES) == {"admin", "user"}


def test_admin_role_has_every_user_action_except_impersonate_admins():
    assert ADMIN_DEFAULT_ROLES["admin"].statements == {
        "user": [
            "create",
            "list",
            "set-role",
            "ban",
            "impersonate",
            "delete",
            "set-password",
            "set-email",
            "get",
            "update",
        ],
        "session": ["list", "revoke", "delete"],
    }
    assert "impersonate-admins" not in ADMIN_DEFAULT_ROLES["admin"].statements["user"]


def test_admin_role_cannot_impersonate_admins():
    response = ADMIN_DEFAULT_ROLES["admin"].authorize({"user": ["impersonate-admins"]})
    assert response["success"] is False


def test_user_default_role_is_empty():
    assert ADMIN_DEFAULT_ROLES["user"].statements == {"user": [], "session": []}


def test_user_default_role_cannot_do_anything():
    response = ADMIN_DEFAULT_ROLES["user"].authorize({"user": ["get"]})
    assert response == {
        "success": False,
        "error": 'unauthorized to access resource "user"',
    }


# --- organization default tables (plugins/organization/access/statement.ts) ----------


def test_org_default_statements_exact():
    assert ORG_DEFAULT_STATEMENTS == {
        "organization": ["update", "delete"],
        "member": ["create", "update", "delete"],
        "invitation": ["create", "cancel"],
        "team": ["create", "update", "delete"],
        "ac": ["create", "read", "update", "delete"],
    }


def test_org_default_roles_keys():
    assert set(ORG_DEFAULT_ROLES) == {"admin", "owner", "member"}


def test_org_owner_role_has_everything():
    assert ORG_DEFAULT_ROLES["owner"].statements == {
        "organization": ["update", "delete"],
        "member": ["create", "update", "delete"],
        "invitation": ["create", "cancel"],
        "team": ["create", "update", "delete"],
        "ac": ["create", "read", "update", "delete"],
    }


def test_org_admin_role_has_everything_except_organization_delete():
    assert ORG_DEFAULT_ROLES["admin"].statements == {
        "organization": ["update"],
        "invitation": ["create", "cancel"],
        "member": ["create", "update", "delete"],
        "team": ["create", "update", "delete"],
        "ac": ["create", "read", "update", "delete"],
    }


def test_org_admin_role_cannot_delete_organization():
    response = ORG_DEFAULT_ROLES["admin"].authorize({"organization": ["delete"]})
    assert response["success"] is False


def test_org_owner_role_can_delete_organization():
    response = ORG_DEFAULT_ROLES["owner"].authorize({"organization": ["delete"]})
    assert response == {"success": True}


def test_org_member_role_is_read_only_ac():
    assert ORG_DEFAULT_ROLES["member"].statements == {
        "organization": [],
        "member": [],
        "invitation": [],
        "team": [],
        "ac": ["read"],
    }


def test_org_member_role_can_read_ac_but_not_write():
    assert ORG_DEFAULT_ROLES["member"].authorize({"ac": ["read"]}) == {"success": True}
    assert ORG_DEFAULT_ROLES["member"].authorize({"ac": ["create"]})["success"] is False
    assert ORG_DEFAULT_ROLES["member"].authorize({"organization": ["update"]})["success"] is False

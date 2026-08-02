"""social_providers accepts name-keyed config dicts, resolved via PROVIDER_REGISTRY,
alongside already-constructed provider instances (mixed forms allowed)."""

import pytest

from better_auth.oauth import GitHub, Google
from conftest import make_auth


def test_dict_form_constructs_provider():
    auth = make_auth(social_providers={"github": {"client_id": "cid", "client_secret": "csecret"}})
    provider = auth.social_providers["github"]
    assert isinstance(provider, GitHub)
    assert provider.client_id == "cid"
    assert provider.client_secret == "csecret"
    assert provider.provider_id == "github"


def test_instance_form_unchanged():
    instance = GitHub(client_id="cid", client_secret="csecret")
    auth = make_auth(social_providers={"github": instance})
    assert auth.social_providers["github"] is instance
    assert instance.provider_id == "github"


def test_mixed_dict_and_instance_form():
    instance = GitHub(client_id="cid1", client_secret="secret1")
    auth = make_auth(
        social_providers={
            "github": instance,
            "google": {"client_id": "cid2", "client_secret": "secret2"},
        }
    )
    assert auth.social_providers["github"] is instance
    google = auth.social_providers["google"]
    assert isinstance(google, Google)
    assert google.client_id == "cid2"


def test_unknown_provider_name_raises_value_error():
    with pytest.raises(ValueError, match="not-a-real-provider"):
        make_auth(social_providers={"not-a-real-provider": {"client_id": "x"}})


def test_dict_missing_required_client_id_errors_clearly():
    # client_secret defaults to "" on ProviderConfig, so client_id is the field whose
    # absence actually blows up construction — the dataclass's own TypeError surfaces.
    with pytest.raises(TypeError):
        make_auth(social_providers={"github": {"client_secret": "secret-only"}})

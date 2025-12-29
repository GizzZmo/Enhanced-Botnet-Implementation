import pytest

from botnet_server_enhanced import CYBER_EDITOR_LANGUAGES


def test_cyber_editor_languages_not_empty():
    assert CYBER_EDITOR_LANGUAGES, "Language list should not be empty"


@pytest.mark.parametrize(
    "lang_id",
    ["javascript", "python", "go", "rust", "java", "csharp", "cpp", "php"],
)
def test_cyber_editor_languages_include_core(lang_id):
    assert any(lang["id"] == lang_id for lang in CYBER_EDITOR_LANGUAGES)


def test_cyber_editor_languages_have_versions():
    assert all(
        isinstance(lang.get("versions"), list) and len(lang["versions"]) >= 1
        for lang in CYBER_EDITOR_LANGUAGES
    )

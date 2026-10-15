from pathlib import Path

import pytest

from ops.sync_llm_config import sync_llm_config


def test_sync_only_replaces_llm_fields_and_removes_stale_role_pins(tmp_path):
    source = tmp_path / "operator.env"
    source.write_text("WINRE_LLM_BASE_URL=https://provider.example/v1\n"
                      "WINRE_LLM_MODEL=new-model\nWINRE_LLM_API_KEY=new-secret\n"
                      "FLARE_SSH_KEY=C:\\operator\\key\nREVAI_LLM_API_KEY=other-secret\n")
    destination = tmp_path / ".env"
    original = ("# driver config\nFLARE_SSH_KEY=/opt/winre/.ssh/flare\n"
                "WINRE_GATEWAY_HOST=\nWINRE_SNAPSHOT_GATE=enforce\n"
                "WINRE_LLM_BASE_URL=https://old.example/v1\nWINRE_LLM_MODEL=old-model\n"
                "WINRE_LLM_API_KEY=old-secret\nWINRE_LLM_VERDICT_MODEL=stale-pin\n")
    destination.write_text(original)
    original_bytes = destination.read_bytes()

    result = sync_llm_config(source, destination)
    updated = destination.read_text()
    assert "FLARE_SSH_KEY=/opt/winre/.ssh/flare" in updated
    assert "WINRE_GATEWAY_HOST=\n" in updated
    assert "WINRE_SNAPSHOT_GATE=enforce" in updated
    assert "WINRE_LLM_MODEL=new-model" in updated
    assert "WINRE_LLM_API_KEY=new-secret" in updated
    assert "stale-pin" not in updated
    assert "REVAI_LLM_API_KEY" not in updated
    assert Path(result["backup"]).read_bytes() == original_bytes
    assert "secret" not in str(result)

    before = destination.read_bytes()
    assert sync_llm_config(source, destination)["changed"] is False
    assert destination.read_bytes() == before


def test_invalid_source_leaves_driver_config_untouched(tmp_path):
    source = tmp_path / "operator.env"
    source.write_text("FLARE_SSH_KEY=C:\\operator\\key\n")
    destination = tmp_path / ".env"
    destination.write_text("FLARE_SSH_KEY=/driver/key\n")
    before = destination.read_bytes()
    with pytest.raises(ValueError, match="WINRE_LLM_BASE_URL"):
        sync_llm_config(source, destination)
    assert destination.read_bytes() == before
    assert not list(tmp_path.glob(".env.bak-*"))


def test_new_driver_must_configure_its_own_transport_first(tmp_path):
    source = tmp_path / "operator.env"
    source.write_text("WINRE_LLM_BASE_URL=https://provider.example/v1\nWINRE_LLM_MODEL=model\n")
    with pytest.raises(FileNotFoundError):
        sync_llm_config(source, tmp_path / ".env")

"""Tests for context sources storage in RunRepository (#125)."""

from __future__ import annotations

from pathlib import Path

from secfoo.storage.repository import RunRepository


def _create_run(repo: RunRepository) -> str:
    project_id = repo.upsert_project("test_proj", "Test Project", "local")
    return repo.create_run(
        project_id=project_id,
        skill_id="sast",
        skill_name="SAST",
        agent_id="claude",
        confluence_urls=[],
    )


def test_context_sources_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    repo = RunRepository(db_path=db_path)
    run_uuid = _create_run(repo)

    rows = [
        ("https://example.com/spec", "URL", True, "reached ok"),
        ("notes.md", "local file", False, "file unread"),
    ]
    repo.replace_context_sources(run_uuid, rows)

    results = repo.list_context_sources(run_uuid)
    assert len(results) == 2

    assert results[0].position == 0
    assert results[0].source == "https://example.com/spec"
    assert results[0].type == "URL"
    assert results[0].reached is True
    assert isinstance(results[0].reached, bool)
    assert results[0].notes == "reached ok"

    assert results[1].position == 1
    assert results[1].source == "notes.md"
    assert results[1].type == "local file"
    assert results[1].reached is False
    assert isinstance(results[1].reached, bool)
    assert results[1].notes == "file unread"

    repo.close()


def test_replace_overwrites_previous_rows_and_preserves_order(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    repo = RunRepository(db_path=db_path)
    run_uuid = _create_run(repo)

    initial_rows = [
        ("src_a", "type_a", True, "note_a"),
        ("src_b", "type_b", False, "note_b"),
        ("src_c", "type_c", True, "note_c"),
    ]
    repo.replace_context_sources(run_uuid, initial_rows)
    assert len(repo.list_context_sources(run_uuid)) == 3

    replacement_rows = [
        ("src_x", "type_x", False, "note_x"),
        ("src_y", "type_y", True, "note_y"),
    ]
    repo.replace_context_sources(run_uuid, replacement_rows)

    results = repo.list_context_sources(run_uuid)
    assert len(results) == 2
    assert results[0].position == 0
    assert results[0].source == "src_x"
    assert results[0].reached is False
    assert results[1].position == 1
    assert results[1].source == "src_y"
    assert results[1].reached is True

    repo.close()


def test_unknown_run_uuid_behavior(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    repo = RunRepository(db_path=db_path)

    assert repo.list_context_sources("non-existent-uuid") == []

    # replace_context_sources on unknown run_uuid is a no-op
    repo.replace_context_sources("non-existent-uuid", [("src", "type", True, "notes")])
    assert repo.list_context_sources("non-existent-uuid") == []

    repo.close()


def test_dropped_table_recreated_on_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    repo = RunRepository(db_path=db_path)
    run_uuid = _create_run(repo)

    repo.replace_context_sources(run_uuid, [("src_1", "type_1", True, "note_1")])
    assert len(repo.list_context_sources(run_uuid)) == 1

    repo._conn.execute("DROP TABLE context_sources")
    repo._conn.commit()
    repo.close()

    # Reopening RunRepository on the same file runs schema.sql and recreates the table
    reopened_repo = RunRepository(db_path=db_path)
    assert reopened_repo.list_context_sources(run_uuid) == []

    reopened_repo.replace_context_sources(run_uuid, [("src_recreated", "type_2", False, "note_2")])
    records = reopened_repo.list_context_sources(run_uuid)
    assert len(records) == 1
    assert records[0].source == "src_recreated"
    assert records[0].reached is False
    assert records[0].notes == "note_2"

    reopened_repo.close()

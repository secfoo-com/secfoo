from __future__ import annotations

import json

from secfoo.stack import Stack, detect_stack, language_for_ecosystem, language_for_path


def test_language_for_path_maps_source_and_config_files():
    assert language_for_path("app/db.py") == "python"
    assert language_for_path("`web/App.tsx`".strip("`")) == "typescript"
    assert language_for_path("deploy/ci.yml") == "yaml"
    assert language_for_path(".env.production") == "dotenv"
    assert language_for_path("Dockerfile") == "dockerfile"
    assert language_for_path("README") is None
    assert language_for_path(None) is None


def test_language_for_ecosystem_is_case_insensitive():
    assert language_for_ecosystem("PyPI") == "python"
    assert language_for_ecosystem("npm") == "javascript"
    assert language_for_ecosystem("crates.io") == "rust"
    assert language_for_ecosystem("unknown-thing") is None
    assert language_for_ecosystem(None) is None


def test_detect_stack_orders_languages_by_file_count_and_reads_manifests(tmp_path):
    (tmp_path / "app").mkdir()
    for name in ("views.py", "models.py", "urls.py"):
        (tmp_path / "app" / name).write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "static.js").write_text("let x = 1;\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("Django==4.2\n# flask is not used\nrequests>=2\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "^18.0.0"}}), encoding="utf-8")

    stack = detect_stack(tmp_path)

    assert stack.languages == ["python", "javascript"]
    assert stack.primary_language == "python"
    assert stack.frameworks_for("python") == ["django"]
    assert stack.frameworks_for("javascript") == ["react"]
    assert stack.all_frameworks() == ["django", "react"]


def test_detect_stack_skips_dependency_and_hidden_directories(tmp_path):
    (tmp_path / "node_modules" / "express").mkdir(parents=True)
    (tmp_path / "node_modules" / "express" / "package.json").write_text(
        json.dumps({"dependencies": {"koa": "1"}}), encoding="utf-8"
    )
    (tmp_path / "node_modules" / "express" / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\n", encoding="utf-8")
    (tmp_path / "go.mod").write_text("module x\nrequire github.com/gin-gonic/gin v1.9.0\n", encoding="utf-8")

    stack = detect_stack(tmp_path)

    assert stack.languages == ["go"]
    assert stack.frameworks == {"go": ["gin"]}


def test_typescript_projects_inherit_package_json_frameworks(tmp_path):
    for name in ("a.ts", "b.ts"):
        (tmp_path / name).write_text("export {}\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"@nestjs/core": "10"}}), encoding="utf-8")

    stack = detect_stack(tmp_path)

    assert stack.primary_language == "typescript"
    assert stack.frameworks_for("typescript") == ["nestjs"]


def test_detect_stack_on_a_missing_directory_is_empty(tmp_path):
    assert detect_stack(tmp_path / "nope") == Stack()
    assert detect_stack(None) == Stack()


def test_pyproject_dependencies_are_detected(tmp_path):
    (tmp_path / "main.py").write_text("", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["fastapi>=0.110", "uvicorn[standard]"]\n', encoding="utf-8"
    )
    assert detect_stack(tmp_path).frameworks_for("python") == ["fastapi"]

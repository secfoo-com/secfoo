from __future__ import annotations

import pytest

from secfoo.skills.loader import SkillLoadError, load_all_skills, load_skill
from secfoo.skills.renderer import TargetContext, render_prompt

EXPECTED_SKILL_IDS = {
    # Focused security activities
    "security-architecture-review",
    "threat-modeling",
    "sast",
    "sca-reachability",
    "secret-scanning",
    "third-party-risk-assessment",
    # AI/deployment activities
    "prompt-review",
    "responsible-ai-compliance",
    "deployment-readiness",
}


def test_load_all_skills_finds_every_known_skill():
    skills = load_all_skills()
    assert set(skills) == EXPECTED_SKILL_IDS
    for skill in skills.values():
        assert skill.name
        assert skill.description
        assert skill.body


def test_load_skill_unknown_raises():
    with pytest.raises(SkillLoadError):
        load_skill("does-not-exist")


def test_render_prompt_includes_safety_preamble_target_and_output_contract(tmp_path):
    skill = load_skill("security-architecture-review")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)

    assert "READ-ONLY" in prompt
    assert str(tmp_path) in prompt
    assert "## Required output format" in prompt
    assert "### [SEVERITY] A1: Finding title" in prompt
    assert skill.body.splitlines()[0] in prompt
    assert "Output ONLY the Markdown document" in prompt
    assert "do not save the report to a file yourself" in prompt.lower()


def test_render_prompt_includes_confluence_section_when_urls_given(tmp_path):
    skill = load_skill("prompt-review")
    ctx = TargetContext(
        kind="github",
        local_path=tmp_path,
        display_source="https://github.com/org/repo",
        confluence_urls=["https://example.atlassian.net/wiki/x"],
    )
    prompt = render_prompt(skill, ctx)
    assert "Confluence" in prompt
    assert "https://example.atlassian.net/wiki/x" in prompt
    assert "https://github.com/org/repo" in prompt


def test_render_prompt_omits_confluence_section_when_no_urls(tmp_path):
    skill = load_skill("prompt-review")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)
    assert "## Additional context (Confluence)" not in prompt


def test_render_prompt_defaults_to_quick_depth(tmp_path):
    skill = load_skill("security-architecture-review")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)
    assert "Scan depth: QUICK" in prompt
    assert "Scan depth: STANDARD" not in prompt


def test_render_prompt_standard_depth_is_explicit_opt_in(tmp_path):
    skill = load_skill("security-architecture-review")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx, depth="standard")
    assert "Scan depth: STANDARD" in prompt
    assert "Scan depth: QUICK" not in prompt


def test_render_prompt_excludes_noise_directories(tmp_path):
    skill = load_skill("security-architecture-review")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)
    assert "node_modules/" in prompt
    assert ".git/" in prompt
    assert "__pycache__/" in prompt






def test_other_skills_keep_the_simpler_shared_contract(tmp_path):
    skill = load_skill("prompt-review")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)

    assert "## Findings Register" in prompt
    assert "Likelihood x Impact" not in prompt
    assert "Security Controls Matrix" not in prompt
    assert "Attack Chains" not in prompt





# ---------------------------------------------------------------------------
# Cross-skill invariants
# ---------------------------------------------------------------------------
# Every skill's report feeds the same downstream pipeline, so these hold
# regardless of which contract a skill uses. Breaking either one makes the
# dashboard silently report zero findings for that skill.


@pytest.mark.parametrize("skill_id", sorted(EXPECTED_SKILL_IDS))
def test_every_skill_contract_requires_the_severity_heading_shape(skill_id, tmp_path):
    """report/severity.py counts findings by matching `### [SEVERITY]`."""
    skill = load_skill(skill_id)
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)
    assert "### [SEVERITY]" in prompt


@pytest.mark.parametrize("skill_id", sorted(EXPECTED_SKILL_IDS))
def test_every_skill_contract_requires_an_overall_risk_rating_line(skill_id, tmp_path):
    """report/severity.py parses this to derive risk badges."""
    skill = load_skill(skill_id)
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)
    assert "**Overall risk rating:**" in prompt


@pytest.mark.parametrize("skill_id", sorted(EXPECTED_SKILL_IDS))
def test_every_skill_contract_forbids_preamble_and_file_writing(skill_id, tmp_path):
    skill = load_skill(skill_id)
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)
    assert "Output ONLY the Markdown document" in prompt
    assert "READ-ONLY" in prompt


# ---------------------------------------------------------------------------
# Focused activity contracts
# ---------------------------------------------------------------------------


def _prompt_for(skill_id: str, tmp_path):
    skill = load_skill(skill_id)
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    return render_prompt(skill, ctx)


def _flat(text: str) -> str:
    """Collapses whitespace runs to a single space, so a multi-word phrase
    assertion doesn't false-negative just because the contract's source
    happens to line-wrap in the middle of it -- the wrap is a source
    formatting choice, not a change in what the phrase says.
    """
    return " ".join(text.split())


def test_architecture_review_is_control_centric_and_evaluative(tmp_path):
    """Asks "is this design sound?" -- control presence/placement/layering,
    design principles, and a milestone-gating verdict.
    """
    prompt = _prompt_for("security-architecture-review", tmp_path)
    assert "# Security Architecture Review Report" in prompt
    assert "## 4. Trust Boundaries" in prompt
    assert "## 5. Security Controls Matrix" in prompt
    assert "## 6. Design Principles Assessment" in prompt
    assert "## 7. Operational & Regulatory Fit" in prompt
    assert "## 11. Documentation vs. Implementation" in prompt
    assert "**Design verdict:**" in prompt
    # Presence, placement and layering are three separate judgements.
    assert "| Control | Present | Correctly placed | Layered behind | Evidence |" in prompt


def test_architecture_review_ccm_domain_conformance(tmp_path):
    prompt = _prompt_for("security-architecture-review", tmp_path)
    assert "## 8. CCM Domain Conformance" in prompt
    assert "CSA Cloud Controls Matrix (CCM v4)" in prompt
    # All 17 real CCM v4 domain codes must appear, in the fixed order the
    # contract specifies -- this is not a taxonomy secfoo invented.
    from secfoo.report.architecture import CCM_DOMAINS

    assert len(CCM_DOMAINS) == 17
    section = prompt.split("## 8. CCM Domain Conformance", 1)[1].split("## 9.", 1)[0]
    positions = [section.index(code) for code, _name in CCM_DOMAINS]
    assert positions == sorted(positions), "CCM domains are out of order in the contract"
    for value in ["Conformant", "Partial", "Non-conformant", "Not Assessed (process-assured)", "Not Applicable"]:
        assert value in section


def test_architecture_review_findings_register_has_standard_column(tmp_path):
    """Powers the "most-deviated standards" dashboard panel -- each finding
    can cite the specific clause it violates.
    """
    prompt = _prompt_for("security-architecture-review", tmp_path)
    assert "| ID | Finding | Severity | Category | Standard | Verdict |" in prompt
    assert "**Standard:**" in prompt
    assert "never guess" in prompt.lower()


def test_architecture_review_requires_diagram_and_boundary_table_cross_referenced_by_id(tmp_path):
    """Trust boundaries and the data flow diagram must be one
    cross-referenced artifact (shared Bn IDs), not two disconnected
    write-ups -- confirmed as a real gap against an actual report where the
    boundary table was excellent but nothing tied it to the diagram.
    """
    prompt = _prompt_for("security-architecture-review", tmp_path)
    assert "## 3. Data Flow Diagram" in prompt
    assert "boundary ID" in prompt
    assert "B1" in prompt and "B2" in prompt
    assert "| ID | Boundary | What crosses it | Enforced by | Gap |" in prompt
    assert "one artifact, not two" in prompt
    # The worked diagram example must itself demonstrate a boundary ID on
    # an edge label, not just describe the rule in prose. Split on the
    # actual fenced block (newline-prefixed) -- the prose above it also
    # mentions "```mermaid" inline as a description of the rule.
    diagram = prompt.split("\n```mermaid\n", 1)[1].split("```", 1)[0]
    assert '"B1:' in diagram


def test_architecture_review_covers_non_adversarial_and_principle_checks(tmp_path):
    prompt = _prompt_for("security-architecture-review", tmp_path)
    for principle in ["Least privilege", "Fail-safe", "Defense in depth",
                      "Blast radius containment", "Separation of duties", "Complete mediation"]:
        assert principle in prompt, f"missing principle: {principle}"
    # Non-adversarial coverage that threat modeling deliberately omits.
    for area in ["disaster recovery", "key management lifecycle", "maintainability"]:
        assert area in prompt, f"missing operational area: {area}"
    assert "SOC 2" in prompt


def test_architecture_review_defers_threat_enumeration_to_threat_modeling(tmp_path):
    """The two activities fail differently and must not converge: this one
    judges structure, threat modeling enumerates adversaries.
    """
    prompt = _prompt_for("security-architecture-review", tmp_path)
    assert "Threat Modeling skill" in prompt
    assert "belong to SAST" in prompt
    # Must not ask for the artifacts that define a threat model.
    assert "## 5. STRIDE Analysis" not in prompt
    assert "Adversary Classes" not in prompt


def test_threat_modeling_is_adversary_centric_and_generative(tmp_path):
    """Asks "what could go wrong, and who would make it go wrong?" -- every
    threat dispositioned, residual risk stated explicitly.
    """
    prompt = _prompt_for("threat-modeling", tmp_path)
    assert "# Threat Modeling Report" in prompt
    assert "## 3. Trust Boundaries & Data Flow" in prompt
    assert "## 4. Assumptions" in prompt
    assert "## 5. Adversary Classes" in prompt
    assert "## 6. STRIDE Analysis" in prompt
    assert "## 7. Privacy Threats (LINDDUN)" in prompt
    assert "## 8. Threat Register" in prompt
    assert "## 10. Attack Chains" in prompt
    assert "## 11. Detection Opportunities" in prompt
    assert "## 12. Residual Risk Statement" in prompt
    assert "Likelihood x Impact" in prompt


def test_threat_modeling_requires_a_disposition_per_threat(tmp_path):
    prompt = _prompt_for("threat-modeling", tmp_path)
    for disposition in ["Mitigated", "Gap", "Accepted", "Transferred"]:
        assert disposition in prompt, f"missing disposition: {disposition}"
    assert "undispositioned threat is an incomplete" in _flat(prompt)
    assert "**Residual risk:**" in prompt


def test_threat_modeling_gates_linddun_on_personal_data(tmp_path):
    prompt = _prompt_for("threat-modeling", tmp_path)
    assert "ONLY if the system processes personal data" in prompt
    assert "do not invent" in prompt.lower()


def test_threat_modeling_defers_design_judgement_to_architecture_review(tmp_path):
    prompt = _prompt_for("threat-modeling", tmp_path)
    assert "Security Architecture Review skill" in prompt
    # Must not ask for the artifacts that define an architecture review.
    assert "Security Controls Matrix" not in prompt
    assert "Design verdict" not in prompt


def test_threat_modeling_requires_boundary_ids_cross_referenced_like_architecture_review(tmp_path):
    prompt = _prompt_for("threat-modeling", tmp_path)
    assert "boundary-crossing edge" in prompt
    assert '"B1:' in prompt
    assert "| ID | Boundary | What crosses it |" in prompt
    assert "one cross-referenced artifact" in _flat(prompt)


def test_threat_modeling_requires_model_depth_declaration(tmp_path):
    prompt = _prompt_for("threat-modeling", tmp_path)
    assert "**Model depth:**" in prompt
    for depth in ["Full", "Feature-level", "Lightweight"]:
        assert depth in prompt


def test_threat_modeling_assumptions_section_has_validity_states(tmp_path):
    prompt = _prompt_for("threat-modeling", tmp_path)
    assert "## 4. Assumptions" in prompt
    for validity in ["Holds", "Falsified", "Unverified"]:
        assert validity in prompt
    assert "must also produce a corresponding threat" in _flat(prompt).lower()


def test_threat_modeling_register_has_archetype_asset_class_and_test_reference(tmp_path):
    prompt = _prompt_for("threat-modeling", tmp_path)
    assert "| ID | Threat | Archetype | Asset Class | Boundary | STRIDE | Severity | Disposition | Test Reference |" in prompt
    for asset_class in ["External Entity", "Process", "Data Store", "Data Flow", "Model/Agent"]:
        assert asset_class in _flat(prompt)
    assert "reusable phrase" in prompt.lower()
    assert "**Test Reference:**" in prompt


def test_section_numbering_has_no_duplicates_in_any_contract(tmp_path):
    """Regression: an inserted section once left two `## 9.` headings."""
    import re

    for skill_id in sorted(EXPECTED_SKILL_IDS):
        prompt = _prompt_for(skill_id, tmp_path)
        numbers = re.findall(r"^## (\d+)\. ", prompt, re.MULTILINE)
        assert len(numbers) == len(set(numbers)), f"{skill_id} has duplicate section numbers: {numbers}"


def test_sast_contract_requires_taint_summary_and_code_fixes(tmp_path):
    prompt = _prompt_for("sast", tmp_path)
    assert "# SAST Report" in prompt
    assert "## 5. Taint Summary" in prompt
    assert "| Source | Sink | Path | Sanitized? |" in prompt
    assert "## 7. Code-Fix Appendix" in prompt
    assert "```diff" in prompt
    assert "Injection" in prompt


def test_sast_contract_requires_a_cvss_v31_vector_not_a_bare_score(tmp_path):
    prompt = _prompt_for("sast", tmp_path)
    assert "CVSS Vector" in prompt
    assert "CVSS v3.1 base vector" in prompt
    assert "AV/AC/PR/UI/S/C/I/A" in prompt
    # The contract must never ask the model to state a numeric score itself
    # -- secfoo computes it from the vector via cvss.py.
    assert "do not also state a numeric score" in prompt


def test_responsible_ai_compliance_has_a_severity_anchor(tmp_path):
    """Every other skill grounds its Overall risk rating in an explicit
    High/Medium/Low rubric -- responsible-ai-compliance previously had
    none, making its rating (which the dashboard collapses to a binary
    high-risk/moderate badge) effectively arbitrary. Regression test for
    that real, dogfooding-found gap.
    """
    prompt = _prompt_for("responsible-ai-compliance", tmp_path)
    assert "**High**" in prompt
    assert "**Medium**" in prompt
    assert "**Low**" in prompt


def test_sca_contract_is_dependency_centric_with_reachability(tmp_path):
    prompt = _prompt_for("sca-reachability", tmp_path)
    assert "# SCA Report" in prompt
    assert "## 2. Dependency Inventory" in prompt
    assert "## 6. Reachability Summary" in prompt
    assert "## 7. Upgrade Plan" in prompt
    assert "## 8. Supply-Chain Hygiene" in prompt
    for verdict in ["Reachable", "Conditionally reachable", "Not reachable"]:
        assert verdict in prompt
    assert "never invent a cve id" in prompt.lower()


def test_secret_scanning_covers_docs_history_and_demands_rotation(tmp_path):
    prompt = _prompt_for("secret-scanning", tmp_path)
    assert "# Secret Scanning Report" in prompt
    assert "## 5. Documentation & Confluence Coverage" in prompt
    assert "Confluence" in prompt
    assert "history" in prompt.lower()
    # Rotation, not deletion, is the required remediation for a live secret.
    assert "rotat" in prompt.lower()
    # Secret values must never be reproduced in full.
    assert "REDACTED" in prompt or "redact" in prompt.lower()


def test_focused_skills_do_not_inherit_the_threat_assessment_contract(tmp_path):
    """The 11-section threat-assessment report shape is deliberately not
    shared -- a dependency upgrade plan has no ATLAS/ATT&CK column.
    """
    for skill_id in ["sast", "sca-reachability", "secret-scanning", "third-party-risk-assessment"]:
        prompt = _prompt_for(skill_id, tmp_path)
        assert "## 11. Code-Fix Appendix" not in prompt
        assert "OWASP LLM" not in prompt


def test_third_party_risk_assessment_contract_rates_all_17_ccm_domains(tmp_path):
    prompt = _prompt_for("third-party-risk-assessment", tmp_path)
    assert "# Third-Party Risk Assessment Report" in prompt
    assert "## 3. CCM Domain Conformance" in prompt
    for code in ["A&A", "AIS", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC", "HRS", "IAM", "IPY", "IVS", "LOG", "SEF", "STA", "TVM", "UEM"]:
        assert f"| {code} |" in prompt
    assert "Not source code" in prompt or "not source code" in prompt.lower()
    assert "### [SEVERITY] V1:" in prompt
    assert "**Overall risk rating:**" in prompt


# ---------------------------------------------------------------------------
# Scope exclusions
# ---------------------------------------------------------------------------


def test_exclude_paths_are_additive_not_a_replacement(tmp_path):
    """Naming one path to exclude must never silently re-enable scanning of
    the built-in exclusions (node_modules/, .git/, ...).
    """
    skill = load_skill("sast")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx, exclude_paths=["vendored-repo/"])

    assert "vendored-repo/" in prompt
    assert "node_modules/" in prompt
    assert ".git/" in prompt
    assert "OUT OF SCOPE" in prompt


def test_no_out_of_scope_section_when_no_extra_excludes(tmp_path):
    skill = load_skill("sast")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx)
    assert "OUT OF SCOPE" not in prompt
    assert "node_modules/" in prompt


def test_exclude_paths_blank_entries_are_ignored(tmp_path):
    skill = load_skill("sast")
    ctx = TargetContext(kind="local", local_path=tmp_path, display_source=str(tmp_path), confluence_urls=[])
    prompt = render_prompt(skill, ctx, exclude_paths=["   ", "", "real-path/"])
    out_of_scope = prompt.split("OUT OF SCOPE", 1)[1].split("\n\n", 1)[0]
    assert "real-path/" in out_of_scope
    # Blank entries must not render as empty `` code spans in the list.
    assert "``," not in out_of_scope and out_of_scope.count("`") == 2


def test_merge_excludes_dedupes_and_preserves_order():
    from secfoo.skills.renderer import merge_excludes

    assert merge_excludes(["a/", "b/"], ["b/", "c/"], None) == ["a/", "b/", "c/"]
    assert merge_excludes([" a/ "], ["a/"]) == ["a/"]
    assert merge_excludes(None, []) == []

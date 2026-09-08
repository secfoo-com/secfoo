-- Indexes only, run separately from schema.sql -- some reference columns
-- (runs.assessment_id) that a pre-existing runs table only gains via
-- RunRepository._migrate(), so these must execute strictly after that
-- migration step runs, not as part of the initial CREATE TABLE script.
CREATE INDEX IF NOT EXISTS idx_runs_project_id ON runs(project_id);
CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_assessment_id ON runs(assessment_id);
CREATE INDEX IF NOT EXISTS idx_assessments_project_id ON assessments(project_id);
CREATE INDEX IF NOT EXISTS idx_assessments_type ON assessments(assessment_type);
-- SQLite unique indexes allow any number of NULLs (each treated as
-- distinct), so pre-existing assessments without a uuid coexist fine.
CREATE UNIQUE INDEX IF NOT EXISTS idx_assessments_uuid ON assessments(assessment_uuid);
CREATE INDEX IF NOT EXISTS idx_assessment_attachments_assessment_id ON assessment_attachments(assessment_id);
CREATE INDEX IF NOT EXISTS idx_ai_bom_items_attachment_id ON ai_bom_items(attachment_id);

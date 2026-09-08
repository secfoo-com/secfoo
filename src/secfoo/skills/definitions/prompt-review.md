---
id: prompt-review
name: Prompt Review
description: Security review of LLM prompts, tool-calling definitions, and agent behavior.
short_name: Prompt Review
version: 1
---

Review this codebase for LLM prompt and agent security issues.

1. **Locate all prompt surfaces.** Find system prompts, prompt templates,
   few-shot examples, and tool/function-calling definitions (schemas,
   allowed tool lists, permission scopes).

2. **Check prompt injection resistance.** Identify places where untrusted
   input (user messages, retrieved documents, tool outputs, web content) is
   concatenated directly into instruction context without delimiters,
   escaping, or a clear boundary between instructions and data. Flag any
   place a downstream actor could smuggle instructions into the model's
   context.

3. **Check tool/function-calling permission scope.** Are LLM-callable tools
   scoped to the minimum needed (read-only where possible), or is the model
   granted broad capabilities (arbitrary shell execution, unrestricted file
   write, unscoped database access, outbound network calls) that go beyond
   what the feature requires?

4. **Check human-in-the-loop / validation before side effects.** Are
   LLM-suggested actions (shell commands, SQL queries, file writes, API
   calls, financial transactions) validated or confirmed before execution,
   or can the model act unattended on unvalidated output?

5. **Check for data leakage.** Are secrets, API keys, or PII ever
   interpolated into prompts, logged in full alongside prompt/response
   pairs, or sent to third-party model providers without the user's
   awareness?

6. **Check guardrail robustness.** Are refusal/safety instructions
   susceptible to being overridden by a crafted user message (jailbreak
   patterns)? Is refusal behavior consistent, or does it rely solely on the
   model's own judgment with no code-level backstop for high-risk actions?

7. **Check rate/cost controls.** Is there any protection against a single
   caller triggering unbounded numbers of expensive model calls (cost or
   availability risk)?

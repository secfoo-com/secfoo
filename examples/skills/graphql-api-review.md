---
id: graphql-api-review
name: GraphQL API Security Review
short_name: GraphQL API
description: Reviews a GraphQL API for authorization gaps, query-cost abuse and schema exposure.
version: 1
output: generic
category: API
---

Review the GraphQL API in this codebase as an attacker with a valid but
low-privilege account would approach it. Find the schema (SDL files, code-first
type definitions, or resolver maps) and the server setup first, then work
through these risks:

- **Authorization in resolvers.** Check every query, mutation and field
  resolver that returns or changes another user's data. Authorization done only
  at the HTTP route or gateway is not enough: nested fields
  (`user { orders { paymentMethod } }`) are reachable from any parent type.
  Flag object-level and field-level checks that are missing or inconsistent.
- **Query cost and depth.** Look for query depth limits, complexity or cost
  analysis, pagination caps (`first`/`last` maximums), and batching or alias
  limits. Unbounded lists and recursive types without limits are a
  denial-of-service finding.
- **Introspection and errors.** Is introspection enabled in production
  configuration? Do error responses include stack traces, SQL, or field
  suggestions that leak the schema?
- **Injection through arguments.** Trace resolver arguments into SQL, NoSQL,
  shell, file paths or downstream HTTP calls without validation.
- **Persisted queries and CSRF.** If GET queries or simple content types are
  accepted, check whether mutations can be triggered cross-site.

For each finding, name the resolver or type and the file and line where the
check is missing, and give the concrete fix (the guard to add, and where).

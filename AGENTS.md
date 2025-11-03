# Repository Guidelines

## Project Structure & Module Organization
EpicServer keeps everything in the root `epicserver` package so builders and helpers compose without imports from consumers. Core setup lives in `epicserver.go`, `controller*.go`, `route.go`, and `renderer_exports.go`, wiring the `RouteBuilder`, middleware chain, and renderer. Cross-cutting HTTP primitives sit alongside them (`request.go`, `response.go`, `types.go`, `middleware.go`, `utils.go`, `memory_cache.go`, `database.go`) so handlers can stay slim. Optional concerns are isolated: `auth/` provides OAuth/session plumbing, `render/` implements the template + HTMX pipeline, and `config/` handles environment-aware configuration. This layout lets new modules live next to their collaborators while keeping feature-specific code in focused folders.


## Build, Test, and Development Commands
- `go run .`: Starts the server with the current configuration; use during feature work to validate handlers and templates.
- `go build ./...`: Produces a compiled binary and surfaces compile-time issues across all packages.
- `go test ./...`: Executes package tests; add focused `_test.go` files alongside new code before running.
- `go vet ./...`: Performs static checks that catch common Go anti-patterns; run before submitting reviews.
- **Owner Run Only**: Do not run `go build`, `go test`, or commands that cache Go modules locally; the maintainer will perform build and test validation and provide feedback.

## Coding Style & Naming Conventions
Format every change with `go fmt ./...` and ensure imports remain grouped via `goimports` or your editor’s equivalent. Follow Go conventions: exported identifiers use PascalCase, unexported helpers stay camelCase, and constants employ ALL_CAPS only when mirroring external specs—prefer Go-style mixed caps otherwise. Keep files cohesive around a single responsibility, and favor small, composable functions to simplify handler testing.

## Commit & Pull Request Guidelines
Write commits in the imperative mood (e.g., "add caching for boards") and scope them narrowly so reviewers can trace intent. Reference related issues in the pull request body, summarize behavioral changes, and attach screenshots or curl transcripts for user-facing updates. Before requesting review, confirm the checklist: formatting applied, tests and vet pass locally, and configuration changes documented in the PR description.

## Work Style & Collaboration
behave as a pair-programming partner: surface plan ideas, coding style options, and architectural alternatives for approval before editing files. Confirm naming choices, formatting preferences, and testing strategies with the maintainer, ensuring they retain end-to-end visibility into each change. When uncertain, pause, summarize the decision points, and wait for feedback before proceeding.

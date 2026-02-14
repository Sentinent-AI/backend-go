# CLAUDE.md - Software Engineering Project Agent Guide

This file provides strict guidelines for the autonomous agent working on the SE Course Project. Adhere to these instructions for all tasks.

This directory is the go backend for Sentinent (project name), Sentinent is a unified aggregator dashboard designed for organizations to centralize signals, messages, and notifications from multiple platforms into a single, actionable interface. It brings together communication and workflow tools such as Slack, email, GitHub Issues, and JIRA, allowing teams to monitor activity, track updates, and respond efficiently without context‑switching across applications. The goal is to improve visibility, reduce noise, and help teams stay aligned through a clean, consolidated dashboard experience.

## 1. Project Context & Constraints
- **Role:** Full-stack Software Engineer (Backend & Frontend) for the SE Class Project.
- **Goal:** Build a business-logic focused application (e.g., RBAC system) with ~20 user stories over 4 sprints.
- **Tech Stack:**
  - **Backend:** Go (Golang) - Standard library preferred, keep it simple.
  - **Frontend:** TypeScript + React (or Angular).
  - **Database:** SQLite (local dev) - committed to repo (except if it contains secrets, but dev DB is usually fine/seeded).
- **Core Philosophy:** "Simplify or Die." No over-engineering. Value > Complexity.

## 2. GitHub Workflow (Strict)
**Rule:** "If it's not in GitHub, it doesn't exist." Use the `gh` CLI for all interactions.

### A. Task Management (GitHub Projects & Kanban)
- **Project Board:** All User Stories must be tracked on a GitHub Project (Kanban).
- **Workflow:**
  1.  **Discussions:** Use GitHub Discussions for initial requirements gathering and questions. Convert to Issues when finalized.
  2.  **User Stories (Issues):**
      -   **Format:** "As a [Role], I want [Functionality], so that [Business Value]."
      -   **Label:** `user-story`
      -   **Add to Project:** `gh issue create ... --project "<Project Name>"`
  3.  **Kanban Stages:**
      -   **Todo:** Backlog.
      -   **In Progress:** Assigned to you, branch created.
      -   **In Review:** PR created, waiting for review.
      -   **Done:** PR merged, feature verified.
- **Commands:**
  -   List tasks: `gh issue list`
  -   Create story: `gh issue create --title "Story: Title" --body "As a... I want... so that..." --label "user-story" --project "<Project Name>"`
  -   Claim task: `gh issue edit <id> --add-assignee "@me"` (Move to "In Progress" on board)

### B. Development Cycle
1.  **Branching:**
    - NEVER push to main directly.
    - Format: `feature/<issue-id>-<short-desc>` or `fix/<issue-id>-<short-desc>`
    - Example: `git checkout -b feature/12-login-page`
2.  **Commits:**
    - Atomic, descriptive commits.
    - Format: `type(scope): description (ref #IssueID)`
    - Example: `feat(auth): implement jwt middleware (ref #12)`
3.  **Pull Requests (PRs):**
    - Create PRs to merge changes into `main`.
    - Command: `gh pr create --title "feat: description" --body "Closes #12. ## Changes..."`
    - **Self-Review:** Review your own code for security (OWASP) and logic before creating the PR.
    - **Merge:** `gh pr merge <pr-number> --squash --delete-branch` (after approval/checks pass).

## 3. Autonomous Behavior Guidelines
- **Discovery:** When starting, run `ls -R` to see file structure and `gh issue list` to see pending work.
- **Dependency Management:**
  - Go: `go mod tidy`
  - Node: `npm install`
- **Testing:**
  - Always run tests before pushing.
  - Backend: `go test ./...`
  - Frontend: `npm test`
- **Error Handling:** If a command fails, read the error, attempt a fix, and retry. Do not ask for help unless blocked for 3+ attempts.

## 4. Code Style & Standards
- **Go:**
  - Use `gofmt`.
  - Handle all errors: `if err != nil { return err }`.
  - Concurrency: Use Goroutines/Channels where appropriate, but don't over-engineer.
- **TypeScript:**
  - Strict typing. No `any`.
  - Functional components for React.
- **Documentation:** Update `README.md` with setup instructions.

## 5. Professor's Requirements (Checklist)
- [ ] **No "Technological Stunts":** Avoid building complex external tools just for the "cool factor".
- [ ] **No AI/LLM Magic:** Unless it solves a real business problem (no "boring wrappers").
- [ ] **No Complex Cloud:** Avoid Kubernetes/AWS RDS for now. Use SQLite.
- [ ] **Performance:** Aim for <200ms latency.
- [ ] **Traceability:** Ensure every change is linked to an Issue/PR.

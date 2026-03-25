package services

import "testing"

func TestSplitGitHubIssuesAndPullRequests(t *testing.T) {
	items := []GitHubIssue{
		{ID: 1, Title: "Issue 1"},
		{
			ID:    2,
			Title: "PR 1",
			PullRequest: &struct {
				URL string `json:"url"`
			}{
				URL: "https://api.github.com/repos/octo/repo/pulls/2",
			},
		},
		{ID: 3, Title: "Issue 2"},
	}

	issues, prs := splitGitHubIssuesAndPullRequests(items)

	if len(issues) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(issues))
	}
	if len(prs) != 1 {
		t.Fatalf("expected 1 pull request, got %d", len(prs))
	}
	if prs[0].ID != 2 {
		t.Fatalf("expected PR id 2, got %d", prs[0].ID)
	}
}

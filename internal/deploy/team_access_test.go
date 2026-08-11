package deploy

import (
	"context"
	"errors"
	"testing"

	"github.com/slime4ik/djaploy-core/internal/cfg"
)

type teamAccessStub struct {
	members map[string]map[string]bool
}

func (s *teamAccessStub) TeamIDsOf(context.Context, string) ([]string, error) { return nil, nil }
func (s *teamAccessStub) IsMember(_ context.Context, teamID, userID string) (bool, error) {
	return s.members[teamID][userID], nil
}
func (s *teamAccessStub) LogActivity(context.Context, string, string, string, string) {}

type installationResolverStub struct {
	githubUser string
	gitlabUser string
}

func (s *installationResolverStub) GetInstallationIDByUserID(_ context.Context, userID string) (int64, error) {
	s.githubUser = userID
	return 0, errors.New("stop before external token request")
}
func (s *installationResolverStub) GitLabToken(_ context.Context, userID string) (string, error) {
	s.gitlabUser = userID
	return "gitlab-token", nil
}

func TestRerunClonePreservesTeamAccess(t *testing.T) {
	src := &Deployment{
		ID: "dep-1", UserID: "owner", TeamID: "team-1", Repo: "org/app",
		Status: StatusSuccess, sshKeyEnc: "encrypted-key",
		ServerState: ServerState{AccessKey: true, Releases: []Release{{SHA: "abc1234"}}},
	}
	live := rerunClone(src, redeploySteps(false))

	if live.TeamID != src.TeamID {
		t.Fatalf("TeamID lost on a rerun: got %q, want %q", live.TeamID, src.TeamID)
	}
	if live.UserID != src.UserID || live.sshKeyEnc != src.sshKeyEnc {
		t.Fatal("a rerun must keep the project owner and the server key")
	}

	svc := &Service{teams: &teamAccessStub{members: map[string]map[string]bool{
		"team-1": {"member": true},
	}}}
	if !svc.canAccess(context.Background(), live, "member") {
		t.Fatal("a team member lost access to the live deploy after an update")
	}
	if svc.canAccess(context.Background(), live, "outsider") {
		t.Fatal("an outsider got access to a team live deploy")
	}
}

func TestTeamProjectAccessRequiresCurrentMembership(t *testing.T) {
	svc := &Service{teams: &teamAccessStub{members: map[string]map[string]bool{
		"team-1": {"member": true},
	}}}
	teamProject := &Deployment{UserID: "creator", TeamID: "team-1"}

	if !svc.canAccess(context.Background(), teamProject, "member") {
		t.Fatal("a current team member must see the team project")
	}
	if svc.canAccess(context.Background(), teamProject, "creator") {
		t.Fatal("a creator who left the team must not keep access")
	}
	personalProject := &Deployment{UserID: "creator"}
	if !svc.canAccess(context.Background(), personalProject, "creator") {
		t.Fatal("a creator must see their own personal project")
	}
}

func TestGitTokenAlwaysUsesProjectCreator(t *testing.T) {
	resolver := &installationResolverStub{}
	svc := &Service{
		cfg:      &cfg.Config{},
		resolver: resolver,
	}

	githubDep := &Deployment{UserID: "project-owner", Repo: "org/private", Provider: ProviderGitHub}
	_, _ = svc.gitToken(context.Background(), githubDep)
	if resolver.githubUser != "project-owner" {
		t.Fatalf("GitHub credentials requested for %q instead of the project owner", resolver.githubUser)
	}

	gitlabDep := &Deployment{UserID: "project-owner", Repo: "org/private", Provider: ProviderGitLab}
	token, de := svc.gitToken(context.Background(), gitlabDep)
	if de != nil || token != "gitlab-token" {
		t.Fatalf("GitLab token: token=%q error=%v", token, de)
	}
	if resolver.gitlabUser != "project-owner" {
		t.Fatalf("GitLab credentials requested for %q instead of the project owner", resolver.gitlabUser)
	}
}

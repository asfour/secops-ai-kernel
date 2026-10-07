package consensus

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

type testAgent struct {
	id   string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newTestAgent(t *testing.T, id string) testAgent {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key for %s: %v", id, err)
	}
	return testAgent{id: id, priv: priv, pub: pub}
}

func (a testAgent) sign(modelArch string, stateDiffHash []byte) *AgentProposal {
	p := &AgentProposal{AgentID: a.id, ModelArch: modelArch, StateDiffHash: stateDiffHash}
	p.Signature = ed25519.Sign(a.priv, SigningMessage(p))
	return p
}

func TestEvaluateProposals_ReachesQuorumWithDistinctSignedAgentsAndArchs(t *testing.T) {
	agentA := newTestAgent(t, "agent-a")
	agentB := newTestAgent(t, "agent-b")

	keys := map[string]ed25519.PublicKey{agentA.id: agentA.pub, agentB.id: agentB.pub}
	cq := NewConsensusQuorum(keys)

	hash := []byte("state-diff-hash-1")
	ch := make(chan *AgentProposal, 2)
	ch <- agentA.sign("gpt-arch", hash)
	ch <- agentB.sign("claude-arch", hash)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	winner, err := cq.EvaluateProposals(ctx, ch)
	if err != nil {
		t.Fatalf("expected quorum to be reached, got error: %v", err)
	}
	if string(winner) != string(hash) {
		t.Fatalf("expected winning hash %q, got %q", hash, winner)
	}
}

func TestEvaluateProposals_RejectsUnregisteredAgent(t *testing.T) {
	registered := newTestAgent(t, "agent-a")
	imposter := newTestAgent(t, "agent-imposter") // never added to the key registry

	keys := map[string]ed25519.PublicKey{registered.id: registered.pub}
	cq := NewConsensusQuorum(keys)
	cq.Timeout = 100 * time.Millisecond

	hash := []byte("state-diff-hash-2")
	ch := make(chan *AgentProposal, 2)
	ch <- registered.sign("gpt-arch", hash)
	ch <- imposter.sign("claude-arch", hash)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := cq.EvaluateProposals(ctx, ch); err == nil {
		t.Fatal("expected timeout: an unregistered agent's vote must never count")
	}
}

func TestEvaluateProposals_RejectsForgedSignature(t *testing.T) {
	agentA := newTestAgent(t, "agent-a")
	agentB := newTestAgent(t, "agent-b")

	keys := map[string]ed25519.PublicKey{agentA.id: agentA.pub, agentB.id: agentB.pub}
	cq := NewConsensusQuorum(keys)
	cq.Timeout = 100 * time.Millisecond

	hash := []byte("state-diff-hash-3")

	// agentB's proposal is signed by agentA's key but claims to be from
	// agentB — simulating a forged/mismatched signature.
	forged := &AgentProposal{AgentID: agentB.id, ModelArch: "claude-arch", StateDiffHash: hash}
	forged.Signature = ed25519.Sign(agentA.priv, SigningMessage(forged))

	ch := make(chan *AgentProposal, 2)
	ch <- agentA.sign("gpt-arch", hash)
	ch <- forged

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := cq.EvaluateProposals(ctx, ch); err == nil {
		t.Fatal("expected timeout: a forged signature must never count")
	}
}

func TestEvaluateProposals_SingleCompromisedAgentCannotFakeHeterogeneity(t *testing.T) {
	compromised := newTestAgent(t, "agent-compromised")
	keys := map[string]ed25519.PublicKey{compromised.id: compromised.pub}
	cq := NewConsensusQuorum(keys)
	cq.Timeout = 100 * time.Millisecond

	hash := []byte("state-diff-hash-4")
	ch := make(chan *AgentProposal, 3)
	// Same agent claims three different "architectures" to try to
	// manufacture both vote count and heterogeneity alone.
	ch <- compromised.sign("gpt-arch", hash)
	ch <- compromised.sign("claude-arch", hash)
	ch <- compromised.sign("llama-arch", hash)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := cq.EvaluateProposals(ctx, ch); err == nil {
		t.Fatal("expected timeout: one AgentID must contribute at most one vote regardless of claimed ModelArch")
	}
}

func TestEvaluateProposals_RequiresArchDiversityNotJustVoteCount(t *testing.T) {
	agentA := newTestAgent(t, "agent-a")
	agentB := newTestAgent(t, "agent-b")
	keys := map[string]ed25519.PublicKey{agentA.id: agentA.pub, agentB.id: agentB.pub}
	cq := NewConsensusQuorum(keys)
	cq.Timeout = 100 * time.Millisecond

	hash := []byte("state-diff-hash-5")
	ch := make(chan *AgentProposal, 2)
	// Two distinct, correctly-signed agents — but identical ModelArch.
	ch <- agentA.sign("gpt-arch", hash)
	ch <- agentB.sign("gpt-arch", hash)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := cq.EvaluateProposals(ctx, ch); err == nil {
		t.Fatal("expected timeout: quorum requires distinct ModelArch representation, not just vote count")
	}
}

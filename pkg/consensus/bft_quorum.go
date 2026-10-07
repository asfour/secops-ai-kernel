package consensus

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"
)

type AgentProposal struct {
	AgentID       string
	ModelArch     string
	StateDiffHash []byte
	Signature     []byte
}

// SigningMessage is the exact byte sequence a proposal's Signature must
// cover. Keeping this exported lets callers (and tests) construct valid
// signatures without duplicating the layout.
func SigningMessage(p *AgentProposal) []byte {
	msg := make([]byte, 0, len(p.AgentID)+len(p.ModelArch)+len(p.StateDiffHash)+2)
	msg = append(msg, p.AgentID...)
	msg = append(msg, ':')
	msg = append(msg, p.ModelArch...)
	msg = append(msg, ':')
	msg = append(msg, p.StateDiffHash...)
	return msg
}

type ConsensusQuorum struct {
	mu sync.Mutex

	// Proposals is keyed by AgentID (a verified identity), not ModelArch.
	//
	// Keying by ModelArch (the previous behavior) meant two distinct
	// agents sharing an architecture silently overwrote each other, and
	// nothing stopped a single compromised agent from submitting several
	// proposals under different *claimed* ModelArch values to manufacture
	// the "heterogeneous" quorum on its own. See
	// docs/improvement_spec.md item #8.
	Proposals map[string]*AgentProposal

	// PublicKeys maps a registered AgentID to the ed25519 key it must
	// sign proposals with. A proposal from an AgentID not in this map, or
	// with a signature that doesn't verify, is dropped before counting.
	PublicKeys map[string]ed25519.PublicKey

	RequiredVotes   int
	RequiredArchDiv int // minimum distinct ModelArch values required among the counted votes
	Timeout         time.Duration
}

func NewConsensusQuorum(publicKeys map[string]ed25519.PublicKey) *ConsensusQuorum {
	return &ConsensusQuorum{
		Proposals:       make(map[string]*AgentProposal),
		PublicKeys:      publicKeys,
		RequiredVotes:   2, // Hard-coded 2-out-of-3 Byzantine Quorum
		RequiredArchDiv: 2, // Preserve the original heterogeneous-model intent
		Timeout:         450 * time.Millisecond,
	}
}

func (cq *ConsensusQuorum) verify(prop *AgentProposal) bool {
	pub, ok := cq.PublicKeys[prop.AgentID]
	if !ok {
		return false
	}
	return ed25519.Verify(pub, SigningMessage(prop), prop.Signature)
}

func (cq *ConsensusQuorum) EvaluateProposals(ctx context.Context, incoming <-chan *AgentProposal) ([]byte, error) {
	timeoutChan := time.After(cq.Timeout)

	for {
		select {
		case prop := <-incoming:
			if prop == nil {
				continue
			}
			if !cq.verify(prop) {
				// Unregistered agent or invalid/forged signature: never
				// counted, regardless of how many times it's resubmitted.
				continue
			}

			cq.mu.Lock()
			// One live proposal per verified AgentID. A later proposal
			// from the same agent replaces its earlier one rather than
			// stacking additional votes.
			cq.Proposals[prop.AgentID] = prop

			hashCounts := make(map[string]map[string]bool) // hash -> set of ModelArch represented
			var winningHash []byte

			for _, p := range cq.Proposals {
				hashStr := fmt.Sprintf("%x", p.StateDiffHash)
				if hashCounts[hashStr] == nil {
					hashCounts[hashStr] = make(map[string]bool)
				}
				hashCounts[hashStr][p.ModelArch] = true
			}

			for hashStr, archSet := range hashCounts {
				voteCount := 0
				for _, p := range cq.Proposals {
					if fmt.Sprintf("%x", p.StateDiffHash) == hashStr {
						voteCount++
					}
				}
				if voteCount >= cq.RequiredVotes && len(archSet) >= cq.RequiredArchDiv {
					winningHash = cq.Proposals[firstAgentWithHash(cq.Proposals, hashStr)].StateDiffHash
				}
			}
			cq.mu.Unlock()

			if winningHash != nil {
				return winningHash, nil
			}

		case <-timeoutChan:
			return nil, fmt.Errorf("0x00_CONSENSUS_TIMEOUT_DEADLOCK")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func firstAgentWithHash(proposals map[string]*AgentProposal, hashStr string) string {
	for agentID, p := range proposals {
		if fmt.Sprintf("%x", p.StateDiffHash) == hashStr {
			return agentID
		}
	}
	return ""
}

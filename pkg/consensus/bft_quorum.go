package consensus

import (
	"context"
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

type ConsensusQuorum struct {
	mu            sync.Mutex
	Proposals     map[string]*AgentProposal
	RequiredVotes int
	Timeout       time.Duration
}

func NewConsensusQuorum() *ConsensusQuorum {
	return &ConsensusQuorum{
		Proposals:     make(map[string]*AgentProposal),
		RequiredVotes: 2, // Hard-coded 2-out-of-3 Byzantine Quorum
		Timeout:       450 * time.Millisecond,
	}
}

func (cq *ConsensusQuorum) EvaluateProposals(ctx context.Context, incoming <-chan *AgentProposal) ([]byte, error) {
	timeoutChan := time.After(cq.Timeout)

	for {
		select {
		case prop := <-incoming:
			if prop == nil {
				continue
			}
			cq.mu.Lock()
			// Enforce structural architecture decoupling (Models must be heterogeneous)
			cq.Proposals[prop.ModelArch] = prop

			// Tabulate agreement vectors
			hashCounts := make(map[string]int)
			var winningHash []byte

			for _, p := range cq.Proposals {
				hashStr := fmt.Sprintf("%x", p.StateDiffHash)
				hashCounts[hashStr]++
				if hashCounts[hashStr] >= cq.RequiredVotes {
					winningHash = p.StateDiffHash
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

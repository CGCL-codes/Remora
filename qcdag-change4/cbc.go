package qcdag4

/*
import (
	"github.com/gitzhang10/BFT/conn"
	"github.com/gitzhang10/BFT/sign"
	"sync"
)
*/
/*
import (
	"crypto/ed25519"
	"github.com/gitzhang10/BFT/conn"
	"github.com/gitzhang10/BFT/sign"
	"sync"
)

type CBC struct {
	name                  string
	clusterAddrWithPorts  map[string]uint8
	connPool              *conn.NetworkTransport
	nodeNum               int
	quorumNum             int
	pendingBlocks         map[uint64]map[string]*Block // map from round to sender to block
	pendingVote           map[uint64]map[string]map[string]*Vote // map from round to block_sender to vote_sender to vote
	privateKey            ed25519.PrivateKey
	lock                  sync.RWMutex
	dataCh                chan Block
	output                map[uint64]map[string]bool // mark whether a block has been output before
}

func(c *CBC) ReturnDataChan() chan Block {
	return c.dataCh
}

func NewCBCer(name string, clusterAddrWithPorts  map[string]uint8, connPool *conn.NetworkTransport, q, n int,
	privateKey ed25519.PrivateKey) *CBC {
	return &CBC{
		name:                 name,
		clusterAddrWithPorts: clusterAddrWithPorts,
		connPool:             connPool,
		nodeNum:              n,
		quorumNum:            q,
		pendingBlocks:        make(map[uint64]map[string]*Block),
		pendingVote:          make(map[uint64]map[string]map[string]*Vote),
		privateKey:           privateKey,
		dataCh:               make(chan Block),
		output:               make( map[uint64]map[string]bool),
	}
}

func(c *CBC) BroadcastBlock(block *Block) {
	err := c.broadcast(ProposalTag, block)
	if err != nil {
		panic(err)
	}
}

func(c *CBC) BroadcastVote(blockSender string, round uint64) {
	vote := Vote{
		VoteSender:  c.name,
		BlockSender: blockSender,
		Round:       round,
	}
	err := c.broadcast(VoteTag, vote)
	if err != nil {
		panic(err)
	}
}

func(c *CBC) HandleBlockMsg(block *Block) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.storeBlockMsg(block)
	c.BroadcastVote(block.Sender, block.Round)
	c.tryToOutputBlocks(block.Round, block.Sender)
}

func(c *CBC) HandleVoteMsg(vote *Vote) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.storeVoteMsg(vote)
	c.checkIfQuorumVote(vote)
}

func(c *CBC) storeBlockMsg(block *Block) {
	if _, ok := c.pendingBlocks[block.Round]; !ok {
		c.pendingBlocks[block.Round] = make(map[string]*Block)
	}
	c.pendingBlocks[block.Round][block.Sender] = block
}

func(c *CBC) storeVoteMsg(vote *Vote) {
	if _, ok := c.pendingVote[vote.Round]; !ok {
		c.pendingVote[vote.Round] = make(map[string]map[string]*Vote)
	}
	if _, ok := c.pendingVote[vote.Round][vote.BlockSender]; !ok {
		c.pendingVote[vote.Round][vote.BlockSender] = make(map[string]*Vote)
	}
	c.pendingVote[vote.Round][vote.BlockSender][vote.VoteSender] = vote
}

func (c *CBC) checkIfQuorumVote(vote *Vote) {
	votes := c.pendingVote[vote.Round][vote.BlockSender]
	if _, ok := c.output[vote.Round]; !ok {
		c.output[vote.Round] = make(map[string]bool)
	}
	if len(votes) >= c.quorumNum {
		c.tryToOutputBlocks(vote.Round, vote.BlockSender)
	}
}

func (c *CBC) tryToOutputBlocks(round uint64, sender string) {
	if c.output[round][sender] {
		return
	}
	if _, ok := c.pendingBlocks[round][sender]; !ok {
		return
	}
	if _, ok := c.pendingVote[round][sender]; !ok {
		return
	}
	votes := c.pendingVote[round][sender]
	if len(votes) >= c.quorumNum {
		block := c.pendingBlocks[round][sender]
		c.dataCh <- *block
		c.output[round][sender] = true
	}
}

// send message to all nodes
func (c *CBC) broadcast(msgType uint8, msg interface{}) error {
	msgAsBytes, err := encode(msg)
	if err != nil {
		return err
	}
	sig := sign.SignEd25519(c.privateKey, msgAsBytes)
	for addrWithPort := range c.clusterAddrWithPorts {
		netConn, err := c.connPool.GetConn(addrWithPort)
		if err != nil {
			return err
		}
		if err = conn.SendMsg(netConn, msgType, msg, sig); err != nil {
			return err
		}

		if err = c.connPool.ReturnConn(netConn); err != nil {
			return err
		}
	}
	return nil
}
*/

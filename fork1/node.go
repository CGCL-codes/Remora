package fork1

import (
	"Remora/config"
	"Remora/conn"
	"Remora/sign"
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"go.dedis.ch/kyber/v3/share"
	"math"
	"reflect"
	"strconv"
	"sync"
	"time"
)

type Node struct {
	name           string
	lock           sync.RWMutex
	chain          *Chain
	candidateChain map[uint64]map[string]map[uint64]*Block // map from view to sender to height to Block
	pendingBlocks  map[string]*Block                       // map from hash to Block
	partialVote    map[uint64]map[uint64]map[string]*Vote  // map from view to height to sender to vote
	finish         map[uint64]map[string]*Finish           // map from view to sender to PartialSig in Finish
	viewChange     map[uint64]map[string]*ViewChange       // map from view to sender to view-change
	done           map[uint64]map[string]*Done             // map from view to sender to Done
	pendingQC      map[uint64]map[string]map[uint64][]byte // map from view to generator to height to QC
	pbStop         uint64                                  // if PB_message's view <= pbStop, node will ignore it
	view           uint64
	leader         map[uint64]string // map from view to leader
	logger         hclog.Logger

	nodeNum   int
	quorumNum int

	clusterAddr          map[string]string // map from name to address
	clusterPort          map[string]int    // map from name to p2pPort
	clusterAddrWithPorts map[string]uint8  // map from addr:port to index
	isFaulty             bool              // true indicate this node is faulty node,
	maxPool              int
	trans                *conn.NetworkTransport
	batchSize            int
	round                uint64 // the number of rounds the protocol will run

	//Used for ED25519 signature
	publicKeyMap map[string]ed25519.PublicKey
	privateKey   ed25519.PrivateKey

	//Used for threshold signature
	tsPublicKey  *share.PubPoly
	tsPrivateKey *share.PriShare

	reflectedTypesMap map[uint8]reflect.Type

	nextView       chan uint64     // inform that the protocol can enter to next view
	block2Send     map[uint64]bool // one view only send one block2
	doneSend       map[uint64]bool // one view only send one done
	finishSend     map[uint64]bool // one view only send one finish
	viewChangeSend map[uint64]bool // one view only send one viewChange

	viewNeedToCommit map[uint64]int // how many views a block need to commit
}

func NewNode(conf *config.Config) *Node {
	var n Node
	n.name = conf.Name
	n.chain = &Chain{blocks: make(map[uint64]*Block), view: 0, height: 0}
	n.chain.blocks[0] = &Block{
		Sender:       "zhang",
		Height:       0,
		View:         0,
		PreviousHash: []byte(""),
		Txs:          [][]byte{},
		QC:           []byte(""),
	}
	n.candidateChain = make(map[uint64]map[string]map[uint64]*Block)
	n.candidateChain[0] = make(map[string]map[uint64]*Block)
	n.candidateChain[0]["zhang"] = make(map[uint64]*Block)
	block := n.chain.blocks[0]
	n.candidateChain[0]["zhang"][0] = block
	n.pendingBlocks = make(map[string]*Block)
	hash, _ := block.getHashAsString()
	n.pendingBlocks[hash] = block
	n.partialVote = make(map[uint64]map[uint64]map[string]*Vote)
	n.finish = make(map[uint64]map[string]*Finish)
	n.viewChange = make(map[uint64]map[string]*ViewChange)
	n.done = make(map[uint64]map[string]*Done)
	n.pendingQC = make(map[uint64]map[string]map[uint64][]byte)
	n.pendingQC[0] = make(map[string]map[uint64][]byte)
	n.pendingQC[0]["zhang"] = make(map[uint64][]byte)
	n.pendingQC[0]["zhang"][0] = []byte("")
	n.pbStop = 0
	n.view = 1
	n.leader = make(map[uint64]string)
	n.leader[0] = "zhang"
	n.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "ForkBFT-node",
		Output: hclog.DefaultOutput,
		Level:  hclog.Level(conf.LogLevel),
	})

	n.clusterAddr = conf.ClusterAddr
	n.clusterPort = conf.ClusterPort
	n.clusterAddrWithPorts = conf.ClusterAddrWithPorts
	n.nodeNum = len(n.clusterAddr)
	n.quorumNum = int(math.Ceil(float64(2*n.nodeNum) / 3.0))
	n.isFaulty = conf.IsFaulty
	n.maxPool = conf.MaxPool
	n.batchSize = conf.BatchSize
	n.round = uint64(conf.Round)

	n.publicKeyMap = conf.PublicKeyMap
	n.privateKey = conf.PrivateKey
	n.tsPrivateKey = conf.TsPrivateKey
	n.tsPublicKey = conf.TsPublicKey

	n.reflectedTypesMap = reflectedTypesMap

	n.nextView = make(chan uint64, 1)
	n.finishSend = make(map[uint64]bool)
	n.block2Send = make(map[uint64]bool)
	n.doneSend = make(map[uint64]bool)
	n.viewChangeSend = make(map[uint64]bool)

	n.viewNeedToCommit = make(map[uint64]int)

	return &n
}

// start the protocol and make it run target rounds
func (n *Node) RunLoop() {
	start := time.Now().UnixNano()
	for {
		if n.view > n.round {
			break
		}

		n.lock.Lock()
		go n.broadcastBlock1(n.view)
		n.lock.Unlock()

		select {
		case <-n.nextView:
		}
	}
	end := time.Now().UnixNano()

	time.Sleep(3 * time.Second)
	latency, throughput := evluation(end-start, n.round, n.viewNeedToCommit, n.batchSize)
	fmt.Println("****************************************")
	fmt.Printf("nodes's average latency (s): %f \n", latency)
	fmt.Printf("node's average throughput (tps): %f \n", throughput)
	fmt.Println("****************************************")
}

func (n *Node) selectHighestQC(view uint64) (uint64, uint64, []byte) {
	qc, ok := n.pendingQC[view][n.leader[view]][1]
	if ok {
		return view, 1, qc
	}
	qc, ok = n.pendingQC[view][n.leader[view]][0]
	if ok {
		return view, 0, qc
	}
	return n.selectHighestQC(view - 1)
}

func (n *Node) checkIfQuorumVote(view uint64, height uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	partialSig, _ := n.partialVote[view][height]
	if len(partialSig) >= n.quorumNum {
		qc := n.generateQC(view, height)
		if height == 0 && !n.block2Send[view] {
			n.block2Send[view] = true
			n.broadcastBlock2(qc, view)
		} else if height == 1 && !n.doneSend[view] {
			n.doneSend[view] = true
			n.broadcastDone(qc, view)
		}
	}
}

func (n *Node) checkIfQuorumDone(view uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	done, _ := n.done[view]
	if len(done) >= n.quorumNum && !n.finishSend[view] {
		n.finishSend[view] = true
		n.broadcastFinish(view)
	}
}

func (n *Node) checkIfEnoughFinish(view uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	finish, _ := n.finish[view]
	f := n.nodeNum - n.quorumNum
	if len(finish) >= f+1 && !n.finishSend[view] {
		n.finishSend[view] = true
		n.broadcastFinish(view)
	}
	if len(finish) >= n.quorumNum && !n.viewChangeSend[view] {
		n.pbStop = view
		n.electLeader(view)
		n.viewChangeSend[view] = true
		n.broadcastViewChange(view)
		n.tryCommitBlock(view)
	}
}

func (n *Node) checkIfQuorumViewChange(view uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	viewChange, _ := n.viewChange[view]
	// go to next view
	if len(viewChange) >= n.quorumNum && n.view == view {
		n.view++
		n.nextView <- n.view
	}
}

func (n *Node) storeVoteMsg(vote *Vote) {
	n.lock.Lock()
	_, ok := n.partialVote[vote.BlockView]
	if !ok {
		n.partialVote[vote.BlockView] = make(map[uint64]map[string]*Vote)
	}
	_, ok = n.partialVote[vote.BlockView][vote.BlockHeight]
	if !ok {
		n.partialVote[vote.BlockView][vote.BlockHeight] = make(map[string]*Vote)
	}
	n.partialVote[vote.BlockView][vote.BlockHeight][vote.Sender] = vote
	n.lock.Unlock()
}

func (n *Node) storeBlockMsg(block *Block) {
	n.lock.Lock()
	_, ok := n.candidateChain[block.View]
	if !ok {
		n.candidateChain[block.View] = make(map[string]map[uint64]*Block)
	}
	_, ok = n.candidateChain[block.View][block.Sender]
	if !ok {
		n.candidateChain[block.View][block.Sender] = make(map[uint64]*Block)
	}
	n.candidateChain[block.View][block.Sender][block.Height] = block

	hashAsString, err := block.getHashAsString()
	if err != nil {
		panic(err)
	}
	n.pendingBlocks[hashAsString] = block
	n.lock.Unlock()
	if block.Height == 1 {
		n.storeQC(block.View, block.Sender, 0, block.QC)
	}
}

func (n *Node) storeQC(view uint64, generator string, height uint64, qc []byte) {
	n.lock.Lock()
	_, ok := n.pendingQC[view]
	if !ok {
		n.pendingQC[view] = make(map[string]map[uint64][]byte)
	}
	_, ok = n.pendingQC[view][generator]
	if !ok {
		n.pendingQC[view][generator] = make(map[uint64][]byte)
	}
	n.pendingQC[view][generator][height] = qc
	n.lock.Unlock()
}

func (n *Node) storeDoneMsg(done *Done) {
	n.lock.Lock()
	_, ok := n.done[done.View]
	if !ok {
		n.done[done.View] = make(map[string]*Done)
	}
	n.done[done.View][done.Sender] = done
	n.lock.Unlock()
	n.storeQC(done.View, done.Sender, 1, done.QC)
}

func (n *Node) storeFinishMsg(finish *Finish) {
	n.lock.Lock()
	_, ok := n.finish[finish.View]
	if !ok {
		n.finish[finish.View] = make(map[string]*Finish)
	}
	n.finish[finish.View][finish.Sender] = finish
	n.lock.Unlock()
}

func (n *Node) storeViewChangeMsg(viewChange *ViewChange) {
	n.lock.Lock()
	_, ok := n.viewChange[viewChange.View]
	if !ok {
		n.viewChange[viewChange.View] = make(map[string]*ViewChange)
	}
	n.viewChange[viewChange.View][viewChange.Sender] = viewChange
	n.lock.Unlock()
	n.storeQC(viewChange.QCView, viewChange.Sender, viewChange.QCHeight, viewChange.HighestQC)
}

// 这里只是简单验证，有待改进
func (n *Node) validateBlock(block *Block) bool {
	n.lock.Lock()
	defer n.lock.Unlock()
	if block.Height == 0 {
		for _, qc := range block.TC {
			if !bytes.Equal(qc, block.QC) {
				return false
			}
		}
	}
	if block.Height == 1 {
		preHash := hex.EncodeToString(block.PreviousHash)
		if block1, ok := n.pendingBlocks[preHash]; ok {
			if block1.Sender != block.Sender || block1.Height != 0 || block1.View != block.View {
				return false
			}
		}
	}
	return true
}

// For concurrency safe: call of this function should be protected in a locking environment.
func (n *Node) tryCommitBlock(view uint64) {
	if leader, ok := n.leader[view]; ok {
		if _, ok := n.done[view][leader]; ok {
			// 可能还没收到区块，有待改进
			block := n.candidateChain[view][leader][0]
			n.tryCommitAncestorBlock(block)
			if view > n.chain.view {
				chainLength := len(n.chain.blocks)
				n.chain.blocks[uint64(chainLength)] = block
				n.chain.view = view
				n.chain.height = 0
				n.logger.Info("commit the block", "node", n.name, "view", view, "height", 0,
					"block-proposer", block.Sender, "linkBlocksNumber", len(block.LinkBlocks))
				n.viewNeedToCommit[2] += len(block.LinkBlocks)
				n.viewNeedToCommit[1] += 1
			}
		}
	}
}

func (n *Node) tryCommitAncestorBlock(block *Block) {
	for {
		previousHash := hex.EncodeToString(block.PreviousHash)
		// 可能没有收到区块，有待改进
		previousBlock := n.pendingBlocks[previousHash]
		if previousBlock.View < n.chain.view {
			break
		} else if previousBlock.View == n.chain.view && previousBlock.Height <= n.chain.height {
			break
		}
		chainLength := len(n.chain.blocks)
		n.chain.blocks[uint64(chainLength)] = previousBlock
		n.chain.view = previousBlock.View
		n.chain.height = previousBlock.Height
		n.logger.Info("commit the ancestor block", "node", n.name, "view", previousBlock.View,
			"height", previousBlock.Height, "block-proposer", previousBlock.Sender,
			"linkBlocksNumber", len(previousBlock.LinkBlocks))
		block = previousBlock
		n.viewNeedToCommit[n.view-previousBlock.View+2] += len(previousBlock.LinkBlocks)
		n.viewNeedToCommit[n.view-previousBlock.View+1] += 1
	}
}

func (n *Node) NewBlock(view uint64, height uint64, previoushash []byte, qc []byte) *Block {
	tx := generateTX(20)
	var batch [][]byte
	var tc [][]byte
	var linkBlocks []string
	for i := 0; i < n.batchSize; i++ {
		batch = append(batch, tx)
	}
	// only block1 need tc and linkBlocks
	if height == 0 {
		// simply append 2f+1 highest qc to tc
		for i := 0; i < n.quorumNum; i++ {
			tc = append(tc, qc)
		}
		// only link blocks in last view
		for sender, blocks := range n.candidateChain[view-1] {
			if sender != n.leader[view-1] {
				for _, block := range blocks {
					hash, _ := block.getHashAsString()
					linkBlocks = append(linkBlocks, hash)
				}
			}
		}
	}
	return &Block{
		Sender:       n.name,
		Height:       height,
		View:         view,
		PreviousHash: previoushash,
		Txs:          batch,
		QC:           qc,
		TC:           tc,
		LinkBlocks:   linkBlocks,
	}
}

func (n *Node) generateQC(view uint64, height uint64) []byte {
	var partialSig [][]byte
	var hash []byte
	for _, vote := range n.partialVote[view][height] {
		partialSig = append(partialSig, vote.PartialSig)
		hash = vote.BlockHash
	}
	qc := sign.AssembleIntactTSPartial(partialSig, n.tsPublicKey, hash, n.quorumNum, n.nodeNum)
	return qc
}

func (n *Node) electLeader(view uint64) {
	var partialSig [][]byte
	data, err := encode(view)
	if err != nil {
		panic(err)
	}
	for _, finish := range n.finish[view] {
		partialSig = append(partialSig, finish.PartialSig)
	}
	qc := sign.AssembleIntactTSPartial(partialSig, n.tsPublicKey, data, n.quorumNum, n.nodeNum)
	qcAsInt := binary.BigEndian.Uint32(qc)
	leaderId := int(qcAsInt) % n.nodeNum
	leaderName := "node" + strconv.Itoa(leaderId)
	n.leader[view] = leaderName
}

func (n *Node) verifySigED25519(peer string, data interface{}, sig []byte) bool {
	pubKey, ok := n.publicKeyMap[peer]
	if !ok {
		n.logger.Error("node is unknown", "node", peer)
		return false
	}
	dataAsBytes, err := encode(data)
	if err != nil {
		n.logger.Error("fail to encode the data", "error", err)
		return false
	}
	ok, err = sign.VerifySignEd25519(pubKey, dataAsBytes, sig)
	if err != nil {
		n.logger.Error("fail to verify the ED25519 signature", "error", err)
		return false
	}
	return ok
}

func (n *Node) IsFaultyNode() bool {
	return n.isFaulty
}

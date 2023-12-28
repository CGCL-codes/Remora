package qcdag

import (
	"Remora/config"
	"Remora/conn"
	"Remora/sign"
	"crypto/ed25519"
	"encoding/binary"
	"github.com/hashicorp/go-hclog"
	"go.dedis.ch/kyber/v3/share"
	"math"
	"reflect"
	"strconv"
	"sync"
	"time"
)

type Node struct {
	name          string
	lock          sync.RWMutex
	dag           map[uint64]map[string]*Block // map from round to sender to block
	grade1Blocks  map[uint64]map[string]*Block // map from round to sender to grade1 block (which cannot immediately commit)
	pendingBlocks map[uint64]map[string]*Block
	chain         *Chain
	leader        map[uint64]string            // map from round to leader
	pendingDone   map[uint64]map[string]*Done  // done msg which cannot process right now
	done          map[uint64]map[string]*Done  // map from round to sender to Done
	elect         map[uint64]map[string][]byte // map from round to sender to sig
	protocolFlag  map[uint64]int               // map decides op path or pe path
	// 0 presents op grbc, 1 presents waiting cbc, 2 presents pe grbc and 3 presents pe cbc

	round     uint64 // current round
	moveRound map[uint64]int
	logger    hclog.Logger

	nodeNum   int
	quorumNum int

	clusterAddr          map[string]string // map from name to address
	clusterPort          map[string]int    // map from name to p2pPort
	clusterAddrWithPorts map[string]uint8  // map from addr:port to index
	isFaulty             bool              // true indicate this node is faulty node

	maxPool     int
	trans       *conn.NetworkTransport
	batchSize   int
	roundNumber uint64 // the number of rounds the protocol will run
	commitRound uint64

	//Used for ED25519 signature
	publicKeyMap map[string]ed25519.PublicKey
	privateKey   ed25519.PrivateKey

	//Used for threshold signature
	tsPublicKey  *share.PubPoly
	tsPrivateKey *share.PriShare

	reflectedTypesMap map[uint8]reflect.Type

	nextRound   chan uint64     // inform that the protocol can enter to next view
	leaderElect map[uint64]bool // mark whether you have elect a leader in a round
	opPathSig   chan bool       // 3f+1 blocks have grade=2

	evaluation []int64 // store the latency of every blocks
	commitTime []int64 // the time that the leader is committed
	cbc        *CBC

	timer *time.Timer
}

func NewNode(conf *config.Config) *Node {
	var n Node
	n.name = conf.Name
	n.dag = make(map[uint64]map[string]*Block)
	n.grade1Blocks = make(map[uint64]map[string]*Block)
	n.pendingBlocks = make(map[uint64]map[string]*Block)
	n.chain = &Chain{
		round:  0,
		blocks: make(map[string]*Block),
	}
	n.commitRound = 0
	block := &Block{
		Sender:       "zhang",
		Round:        0,
		PreviousHash: nil,
		Txs:          nil,
		TimeStamp:    0,
	}
	hash, _ := block.getHashAsString()
	n.chain.blocks[hash] = block
	n.leader = make(map[uint64]string)
	n.done = make(map[uint64]map[string]*Done)
	n.pendingDone = make(map[uint64]map[string]*Done)
	n.elect = make(map[uint64]map[string][]byte)
	n.protocolFlag = make(map[uint64]int)
	n.round = 1
	n.protocolFlag[1] = 0
	n.moveRound = make(map[uint64]int)
	n.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "QCDAG-node",
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
	n.roundNumber = uint64(conf.Round)
	n.publicKeyMap = conf.PublicKeyMap
	n.privateKey = conf.PrivateKey
	n.tsPrivateKey = conf.TsPrivateKey
	n.tsPublicKey = conf.TsPublicKey

	n.reflectedTypesMap = reflectedTypesMap

	n.nextRound = make(chan uint64, 1)
	n.opPathSig = make(chan bool, 1)
	n.leaderElect = make(map[uint64]bool)
	return &n
}

// start the protocol and make it run target rounds
func (n *Node) RunLoop() {
	var currentRound uint64
	currentRound = 1
	//n.timer = time.NewTimer(100 * time.Millisecond)
	start := time.Now().UnixNano()
	for {
		if currentRound > n.roundNumber {
			break
		}
		//n.timer.Reset(100 * time.Millisecond)
		go n.handlePendingDone(currentRound)
		go n.broadcastBlock(currentRound)
		if n.protocolFlag[currentRound] == 3 {
			go n.broadcastElect(currentRound)
		}
		select {
		case currentRound = <-n.nextRound:
		}
	}
	// wait all blocks are committed
	time.Sleep(5 * time.Second)

	n.lock.Lock()
	end := n.commitTime[len(n.commitTime)-1]
	pastTime := float64(end-start) / 1e9
	blockNum := len(n.evaluation)
	throughPut := float64(blockNum*n.batchSize) / pastTime
	totalTime := int64(0)
	for _, t := range n.evaluation {
		totalTime += t
	}
	latency := float64(totalTime) / 1e9 / float64(blockNum)
	n.lock.Unlock()

	n.logger.Info("the average", "latency", latency, "throughput", throughPut)
	n.logger.Info("the total commit", "block number", blockNum, "time", pastTime)
}

func (n *Node) InitCBC(conf *config.Config) {
	n.cbc = NewCBCer(n.name, conf.ClusterAddrWithPorts, n.trans, n.quorumNum, n.nodeNum, n.privateKey, n.tsPublicKey,
		n.tsPrivateKey)
}

// select at least 2f+1 blocks in last round
func (n *Node) selectPreviousBlocks(round uint64) map[string][]byte {
	n.lock.Lock()
	defer n.lock.Unlock()
	var previousHash map[string][]byte
	previousHash = make(map[string][]byte)
	if round == 0 {
		previousHash = nil
		return previousHash
	}
	for sender, block := range n.dag[round] {
		hash, _ := block.getHash()
		previousHash[sender] = hash
	}
	return previousHash
}

func (n *Node) storeDone(done *Done) {
	if _, ok := n.done[done.Round]; !ok {
		n.done[done.Round] = make(map[string]*Done)
	}
	if _, ok := n.done[done.Round][done.BlockSender]; !ok {
		n.done[done.Round][done.BlockSender] = done
		n.moveRound[done.Round]++
	}
}

func (n *Node) storePendingDone(done *Done) {
	if _, ok := n.pendingDone[done.Round]; !ok {
		n.pendingDone[done.Round] = make(map[string]*Done)
	}
	if _, ok := n.pendingDone[done.Round][done.BlockSender]; !ok {
		n.pendingDone[done.Round][done.BlockSender] = done
	}
}

func (n *Node) storeElectMsg(elect *Elect) {
	if _, ok := n.elect[elect.Round]; !ok {
		n.elect[elect.Round] = make(map[string][]byte)
	}
	n.elect[elect.Round][elect.Sender] = elect.PartialSig
}

/*
func (n *Node) storeGrade1Blocks(block *Block) {
	if _, ok := n.grade1Blocks[block.Round]; !ok {
		n.grade1Blocks[block.Round] = make(map[string]*Block)
	}
	n.grade1Blocks[block.Round][block.Sender] = block
}
*/

func (n *Node) storePendingBlocks(block *Block) {
	if _, ok := n.pendingBlocks[block.Round]; !ok {
		n.pendingBlocks[block.Round] = make(map[string]*Block)
	}
	n.pendingBlocks[block.Round][block.Sender] = block
}

func (n *Node) tryToUpdateDAG(block *Block) {
	n.lock.Lock()
	defer n.lock.Unlock()

	/*
		if n.protocolFlag[block.Round] == 0 || n.protocolFlag[block.Round] == 2 {
			if _, ok := n.done[block.Round][block.Sender]; !ok {
				return
			}
		}
	*/

	if n.checkWhetherCanAddToDAG(block) {
		if _, ok := n.dag[block.Round]; !ok {
			n.dag[block.Round] = make(map[string]*Block)
		}
		n.dag[block.Round][block.Sender] = block

		//difference
		if n.protocolFlag[block.Round] == 0 {
			n.tryToCommitOPLeader(block.Round)
		} else if n.protocolFlag[block.Round] == 2 {
			n.tryToCommitLeader(block.Round)
		} else {
			n.moveRound[block.Round]++
			go n.tryToNextRound(block.Round)
		}
		/*
			if block.Round%2 == 0 {
				n.moveRound[block.Round]++
				go n.tryToNextRound(block.Round)
			} else {
				n.tryToCommitLeader(block.Round)
			}
		*/
		go n.tryToUpdateDAGFromPending(block.Round + 1)
	} else {
		n.storePendingBlocks(block)
	}
}

func (n *Node) tryToUpdateDAGFromPending(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if _, ok := n.pendingBlocks[round]; !ok {
		return
	}
	for sender, block := range n.pendingBlocks[round] {
		delete(n.pendingBlocks[round], sender)
		go n.tryToUpdateDAG(block)
	}
}

func (n *Node) checkWhetherCanAddToDAG(block *Block) bool {
	// simply check whether the block's link-blocks all in DAG
	linkHash := block.PreviousHash
	for sender := range linkHash {
		if _, ok := n.dag[block.Round-1][sender]; !ok {
			return false
		}
	}
	return true
}

func (n *Node) checkOPFastPath(round uint64) {
	if len(n.done[round]) == n.nodeNum && round == n.round {
		n.opPathSig <- true
	}
}

func (n *Node) tryToElectLeader(round uint64) {
	elect, _ := n.elect[round]
	if len(elect) >= n.quorumNum && !n.leaderElect[round] {
		n.leaderElect[round] = true
		var partialSig [][]byte
		data, err := encode(round)
		if err != nil {
			panic(err)
		}
		for _, sig := range elect {
			partialSig = append(partialSig, sig)
		}
		qc := sign.AssembleIntactTSPartial(partialSig, n.tsPublicKey, data, n.quorumNum, n.nodeNum)
		qcAsInt := binary.BigEndian.Uint32(qc)
		leaderId := int(qcAsInt) % n.nodeNum
		leaderName := "node" + strconv.Itoa(leaderId)
		// elect the leader in last round and try to commit
		n.leader[round-1] = leaderName
		//n.logger.Info("hhh")
		n.tryToCommitLeader(round - 1)
	}
}

func (n *Node) tryToNextRound(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if round != n.round {
		return
	}
	count := n.moveRound[round]

	//change
	//with problem
	if count >= n.quorumNum {
		/*
			if n.name == "node0" {
				n.logger.Info("Msg", "CurRound", n.round, "MoveNum", count, "ProtocolFlag", n.protocolFlag[n.round])
			}
		*/
		n.round++
		// simply add pe path
		if n.round%8 == 2 {
			//turn to pe path, start waiting round
			n.protocolFlag[n.round] = 1
		} else {
			/*
				if n.protocolFlag[n.round-1] == 4 {
					//println("anyone", n.name)
					n.protocolFlag[n.round] = 0
					// pe path turns to op path
				} else */
			if n.protocolFlag[n.round-1] == 1 {
				// after waiting round, step into pe path's grbc
				n.protocolFlag[n.round] = 2
			} else if n.protocolFlag[n.round-1] == 2 {
				// step into pe path's cbc
				n.protocolFlag[n.round] = 3
			} else if n.protocolFlag[n.round-1] == 3 {
				// pe path's loop
				n.protocolFlag[n.round] = 0
			}
			/*
				else if n.protocolFlag[n.round-1] == 0 {
					n.protocolFlag[n.round] = 0
				}

			*/
		}
		go func() {
			n.nextRound <- round + 1
		}()
		//go n.tryToNextRound(round + 1)
	}
}

func (n *Node) tryToCommitOPLeader(round uint64) {
	if round <= n.chain.round {
		return
	}
	opLeader := "node" + strconv.Itoa(int(round)%n.nodeNum)

	if _, ok := n.done[round][opLeader]; ok {
		if _, ok := n.dag[round][opLeader]; ok {
			//n.tryToCommitAncestorLeader(round)
			block := n.dag[round][opLeader]
			hash, _ := block.getHashAsString()
			n.chain.round = round
			n.chain.blocks[hash] = block
			n.commitRound = block.Round
			n.logger.Info("commit the opLeader block", "node", n.name, "round", round, "block-proposer", block.Sender)
			commitTime := time.Now().UnixNano()
			latency := commitTime - block.TimeStamp
			n.evaluation = append(n.evaluation, latency)
			n.commitAncestorOPBlocks(round)
			endTime := time.Now().UnixNano()
			n.commitTime = append(n.commitTime, endTime)
		}
	}
}

// commit a valid leader
func (n *Node) tryToCommitLeader(round uint64) {
	if round <= n.chain.round {
		return
	}
	if _, ok := n.leader[round]; ok {
		if _, ok := n.done[round][n.leader[round]]; ok {
			if _, ok := n.dag[round][n.leader[round]]; ok {
				n.tryToCommitAncestorLeader(round)
				block := n.dag[round][n.leader[round]]
				hash, _ := block.getHashAsString()
				n.chain.round = round
				n.chain.blocks[hash] = block
				n.logger.Info("commit the leader block", "node", n.name, "round", round, "block-proposer", block.Sender)
				commitTime := time.Now().UnixNano()
				latency := commitTime - block.TimeStamp
				n.evaluation = append(n.evaluation, latency)
				n.commitAncestorBlocks(round)
				endTime := time.Now().UnixNano()
				n.commitTime = append(n.commitTime, endTime)
				//n.lock.Lock()
				//temp covered
				//n.protocolFlag[round+1] = 4
				//n.lock.Unlock()
			}
		}
	}
}

// commit a valid leader's all uncommitted valid ancestor leader
func (n *Node) tryToCommitAncestorLeader(round uint64) {
	if round < 2 {
		return
	}
	if round-2 <= n.chain.round {
		return
	}
	validLeader := n.findValidLeader(round)
	// for i := uint64(1); i < round; i = i + 2
	for i := n.commitRound; i < round; i = i + 2 {
		if _, ok := validLeader[i]; ok {
			block := n.dag[i][n.leader[i]]
			hash, _ := block.getHashAsString()
			n.chain.round = i
			n.chain.blocks[hash] = block
			n.logger.Info("commit the ancestor leader block", "node", n.name, "round", i, "block-proposer", block.Sender)
			commitTime := time.Now().UnixNano()
			latency := commitTime - block.TimeStamp
			n.evaluation = append(n.evaluation, latency)
			n.commitAncestorBlocks(i)
		}
	}
}

// find all uncommitted valid ancestor leader
func (n *Node) findValidLeader(round uint64) map[uint64]string {
	templeBlocks := make(map[uint64]map[string]*Block)
	block := n.dag[round][n.leader[round]]
	hash, _ := block.getHashAsString()
	templeBlocks[round] = make(map[string]*Block)
	templeBlocks[round][hash] = block
	validLeader := make(map[uint64]string)

	r := round
	for {
		templeBlocks[r-1] = make(map[string]*Block)
		for _, b := range templeBlocks[r] {
			if b.Round%2 == 1 && b.Sender == n.leader[b.Round] {
				validLeader[b.Round] = b.Sender
			}
			for sender := range b.PreviousHash {
				linkBlock := n.dag[r-1][sender]
				hash, _ := linkBlock.getHashAsString()
				templeBlocks[r-1][hash] = linkBlock
			}
		}
		r--
		if r == 0 || r == n.chain.round {
			break
		}
	}
	return validLeader
}

func (n *Node) commitAncestorOPBlocks(round uint64) {
	opLeader := "node" + strconv.Itoa(int(round)%n.nodeNum)
	templeBlocks := make(map[uint64]map[string]*Block)
	block := n.dag[round][opLeader]
	hash, _ := block.getHashAsString()
	templeBlocks[round] = make(map[string]*Block)
	templeBlocks[round][hash] = block
	r := round
	for {
		templeBlocks[r-1] = make(map[string]*Block)
		for hash, b := range templeBlocks[r] {
			if _, ok := n.chain.blocks[hash]; !ok {
				n.chain.blocks[hash] = b
				commitTime := time.Now().UnixNano()
				latency := commitTime - b.TimeStamp
				n.evaluation = append(n.evaluation, latency)
			}
			for sender := range b.PreviousHash {
				linkBlock := n.dag[r-1][sender]
				h, _ := linkBlock.getHashAsString()
				if _, ok := n.chain.blocks[h]; !ok {
					templeBlocks[r-1][h] = linkBlock
				}
			}
		}
		if len(templeBlocks[r-1]) == 0 {
			break
		}
		r--
	}
}

// commit the leader's all uncommitted ancestor blocks
func (n *Node) commitAncestorBlocks(round uint64) {
	templeBlocks := make(map[uint64]map[string]*Block)
	block := n.dag[round][n.leader[round]]
	hash, _ := block.getHashAsString()
	templeBlocks[round] = make(map[string]*Block)
	templeBlocks[round][hash] = block
	r := round
	for {
		templeBlocks[r-1] = make(map[string]*Block)
		for hash, b := range templeBlocks[r] {
			if _, ok := n.chain.blocks[hash]; !ok {
				n.chain.blocks[hash] = b
				commitTime := time.Now().UnixNano()
				latency := commitTime - b.TimeStamp
				n.evaluation = append(n.evaluation, latency)
			}
			for sender := range b.PreviousHash {
				linkBlock := n.dag[r-1][sender]
				h, _ := linkBlock.getHashAsString()
				if _, ok := n.chain.blocks[h]; !ok {
					templeBlocks[r-1][h] = linkBlock
				}
			}
		}
		if len(templeBlocks[r-1]) == 0 {
			break
		}
		r--
	}
}

func (n *Node) NewBlock(round uint64, previousHash map[string][]byte) *Block {
	var batch [][]byte
	tx := generateTX(250)
	for i := 0; i < n.batchSize; i++ {
		batch = append(batch, tx)
	}
	timestamp := time.Now().UnixNano()
	return &Block{
		Sender:       n.name,
		Round:        round,
		PreviousHash: previousHash,
		Txs:          batch,
		TimeStamp:    timestamp,
	}
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

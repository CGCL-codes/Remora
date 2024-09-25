package RemoraC

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
	savingHelpMsg map[uint64]map[string]*HelpMsg // Receiving helpMsg to help invoke ABA

	abaMap        map[uint64]*ABA
	abaFinish     map[uint64]bool
	chain         *Chain
	leader        map[uint64]string            // map from round to leader
	done          map[uint64]map[string]*Done  // map from round to sender to Done
	elect         map[uint64]map[string][]byte // map from round to sender to sig
	protocolFlag  map[uint64]int               // map decides op path or pe path
	doneEnoughSig map[uint64]bool
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

	nextRound         chan uint64          // inform that the protocol can enter to next view
	leaderElect       map[uint64]bool      // mark whether you have elect a leader in a round
	opPathSig         chan uint64          // 3f+1 blocks have grade=2
	canMoveNext       map[uint64]chan bool // 2f+1 received, which can move to next round
	leaderBlockArrive map[uint64]chan bool // opLeader arrive
	RoundType         chan RoundMsg        // round type, same as protocolType

	// ABA Sig
	whetherSendHelp map[uint64]bool
	ABAReturnCH     map[uint64]chan bool
	noNeedABA       map[uint64]chan bool
	pathChange      map[uint64]chan bool

	evaluation []int64 // store the latency of every blocks
	commitTime []int64 // the time that the leader is committed
	cbc        *CBC

	timer      *time.Timer
	timeConfig int
}

func NewNode(conf *config.Config) *Node {
	var n Node
	n.name = conf.Name
	n.abaMap = make(map[uint64]*ABA)
	n.abaFinish = make(map[uint64]bool)
	n.dag = make(map[uint64]map[string]*Block)
	n.grade1Blocks = make(map[uint64]map[string]*Block)
	n.savingHelpMsg = make(map[uint64]map[string]*HelpMsg)
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
	n.elect = make(map[uint64]map[string][]byte)
	n.protocolFlag = make(map[uint64]int)
	n.doneEnoughSig = make(map[uint64]bool)
	n.round = 1
	n.protocolFlag[1] = 0
	n.timeConfig = conf.TimeCon
	n.timer = time.NewTimer(time.Duration(conf.TimeCon) * time.Millisecond)
	n.moveRound = make(map[uint64]int)
	n.logger = hclog.New(&hclog.LoggerOptions{
		Name:   "Remora-node",
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

	// n.nextRound = make(chan uint64, 1)
	n.opPathSig = make(chan uint64, 1)
	// n.roundType = make(chan RoundMsg, n.roundNumber)
	n.canMoveNext = make(map[uint64]chan bool)
	n.leaderElect = make(map[uint64]bool)
	n.leaderBlockArrive = make(map[uint64]chan bool)
	n.ABAReturnCH = make(map[uint64]chan bool)
	n.noNeedABA = make(map[uint64]chan bool)
	n.whetherSendHelp = make(map[uint64]bool)
	n.pathChange = make(map[uint64]chan bool)
	return &n
}

func (n *Node) InitialRoundProcessChannel() {
	n.nextRound = make(chan uint64, n.roundNumber)
	n.RoundType = make(chan RoundMsg, n.roundNumber)
}

// start the protocol and make it run target rounds
func (n *Node) RunLoop() {
	var currentRound uint64
	currentRound = 1
	// n.timer = time.NewTimer(10 * time.Millisecond)
	// n.roundType = make(chan RoundMsg, n.roundNumber)
	start := time.Now().UnixNano()
	// initial setting
	initialRound := RoundMsg{
		Round: 1,
		Type:  0,
	}
	n.RoundType <- initialRound

	for {
		if currentRound > n.roundNumber {
			break
		}
		if n.protocolFlag[currentRound] == 3 {
			go n.broadcastElect(currentRound)
		}
		go n.broadcastBlock(currentRound)
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

func (n *Node) ReturnRoundType() chan RoundMsg {
	return n.RoundType
}

func (n *Node) InitCBC(conf *config.Config) {
	n.cbc = NewCBCer(n.name, conf.ClusterAddrWithPorts, n.trans, n.quorumNum, n.nodeNum, n.privateKey, n.tsPublicKey,
		n.tsPrivateKey)
}

func (n *Node) UpdateABACondition(round uint64) {
	n.lock.Lock()
	n.abaFinish[round] = true
	n.lock.Unlock()
}

func (n *Node) initialOPPathSig(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if _, ok := n.leaderBlockArrive[round]; !ok {
		ch := make(chan bool, 1)
		n.leaderBlockArrive[round] = ch
	}

	if _, ok := n.canMoveNext[round]; !ok {
		ch := make(chan bool, 1)
		n.canMoveNext[round] = ch
	}
}

func (n *Node) initialABASig(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if _, ok := n.ABAReturnCH[round]; !ok {
		ch := make(chan bool, 1)
		n.ABAReturnCH[round] = ch
	}

	if _, ok := n.noNeedABA[round]; !ok {
		ch := make(chan bool, 1)
		n.noNeedABA[round] = ch
	}

}

func (n *Node) initialABA(round uint64) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if _, ok := n.abaMap[round]; !ok {
		n.abaMap[round] = NewABA(n, round)
		go n.initialABASig(round)
	}
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

func (n *Node) storeElectMsg(elect *Elect) {
	if _, ok := n.elect[elect.Round]; !ok {
		n.elect[elect.Round] = make(map[string][]byte)
	}
	n.elect[elect.Round][elect.Sender] = elect.PartialSig
}

func (n *Node) storePendingBlocks(block *Block) {
	if _, ok := n.pendingBlocks[block.Round]; !ok {
		n.pendingBlocks[block.Round] = make(map[string]*Block)
	}
	n.pendingBlocks[block.Round][block.Sender] = block
}

func (n *Node) tryToUpdateDAG(block *Block) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.checkWhetherCanAddToDAG(block) {
		if _, ok := n.dag[block.Round]; !ok {
			n.dag[block.Round] = make(map[string]*Block)
		}
		n.dag[block.Round][block.Sender] = block

		//difference
		if n.protocolFlag[block.Round] == 0 {
		} else if n.protocolFlag[block.Round] == 2 {
			n.tryToCommitLeader(block.Round)
		} else {
			n.moveRound[block.Round]++
			go n.tryToNextRound(block.Round)
		}
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

func (n *Node) processOPPath(round uint64) {
	n.tryToCommitOPLeader(round)
	go n.tryToNextRound(round)
}

func (n *Node) exchangeHelpMsg(round uint64, opLeader string) {
	helpMsg := HelpMsg{
		Round:       round,
		HelpSender:  n.name,
		BlockSender: opLeader,
		LBlockExist: 2,
	}
	n.lock.Lock()
	n.whetherSendHelp[round] = true
	n.lock.Unlock()

	if _, ok := n.done[round][opLeader]; ok {
		n.broadcastHelpMsg(helpMsg)
	} else if _, ok1 := n.dag[round][opLeader]; ok1 {
		helpMsg.LBlockExist = 1
		n.broadcastHelpMsg(helpMsg)
	} else {
		helpMsg.LBlockExist = 0
		n.broadcastHelpMsg(helpMsg)
	}
}

func (n *Node) startABAProcess(round uint64, opLeader string) {
	helpMsg := HelpMsg{
		Round:       round,
		HelpSender:  n.name,
		BlockSender: opLeader,
		LBlockExist: 2,
	}
	n.lock.Lock()
	n.whetherSendHelp[round] = true
	n.lock.Unlock()

	if _, ok := n.done[round][opLeader]; ok {
		n.broadcastHelpMsg(helpMsg)
	} else if _, ok1 := n.dag[round][opLeader]; ok1 {
		helpMsg.LBlockExist = 1
		n.broadcastHelpMsg(helpMsg)
	} else {
		helpMsg.LBlockExist = 0
		n.broadcastHelpMsg(helpMsg)
	}
}

func (n *Node) processOPPathWhileTimerExpire(round uint64) {
	opLeader := "node" + strconv.Itoa(int(round)%n.nodeNum)

	select {
	case <-n.canMoveNext[n.round]:
		n.lock.Lock()
		if _, ok := n.done[round][opLeader]; ok {
			n.lock.Unlock()
			n.logger.Info("1-1", "name", n.name, "round", round)
			n.processOPPath(round)
		} else {
			n.lock.Unlock()
			n.exchangeHelpMsg(round, opLeader)
			n.logger.Info("1-2", "name", n.name, "round", round)
			select {
			case <-n.noNeedABA[round]:
				<-n.leaderBlockArrive[round]
				n.logger.Info("1-2-1", "name", n.name, "round", round)
				n.processOPPath(round)
			case sig := <-n.ABAReturnCH[round]:
				if sig {
					select {
					case <-n.leaderBlockArrive[round]:
						n.logger.Info("1-2-2", "name", n.name, "round", round)
						n.processOPPath(round)
					}
				} else {
					n.logger.Info("BADopLeader!", "name", n.name, "round", round)
					ch := make(chan bool, 1)
					n.pathChange[round] = ch
					n.pathChange[round] <- true
					go n.tryToNextRound(round)
				}
			}
		}

	}
}

func (n *Node) processOPPathWhileCanMoveNextRound(round uint64) {
	opLeader := "node" + strconv.Itoa(int(round)%n.nodeNum)

	n.lock.Lock()
	if _, ok := n.done[round][opLeader]; ok {
		n.lock.Unlock()
		n.processOPPath(round)
	} else {
		n.lock.Unlock()
		select {
		case <-n.timer.C:
			n.exchangeHelpMsg(round, opLeader)
			select {
			case <-n.noNeedABA[round]:
				<-n.leaderBlockArrive[round]
				n.processOPPath(round)
			case sig := <-n.ABAReturnCH[round]:
				if sig {
					select {
					case <-n.leaderBlockArrive[round]:
						n.processOPPath(round)
					}
				} else {
					n.logger.Info("BADopLeader!", "name", n.name, "round", round)
					ch := make(chan bool, 1)
					n.pathChange[round] = ch
					n.pathChange[round] <- true
					go n.tryToNextRound(round)
				}
			}
		case <-n.leaderBlockArrive[round]:
			n.processOPPath(round)
		}
	}
}

/*
func (n *Node) checkConditionWhileTimerExpire(round uint64) {
	opLeader := "node" + strconv.Itoa(int(round)%n.nodeNum)
	if len(n.done[round]) >= n.quorumNum {
		if _, ok := n.done[round][opLeader]; ok {
			// n.logger.Info("case1-1", "Name", n.name, "Round", round)
			n.tryToCommitOPLeader(round)
			<-n.leaderBlockArrive
			<-n.canMoveNext
			n.tryToNextRound(round)
		} else {
			<-n.canMoveNext
			n.logger.Info("case1-2", "Name", n.name, "Round", round)
			n.startABAProcess(round, opLeader)
			select {
			case <-n.noNeedABA:
				select {
				case <-n.leaderBlockArrive:
					// n.logger.Info("case1-2", "Name", n.name, "Round", round)
					n.startABAWithOpResult(round)
				}
			case sig := <-n.ABAReturnCH:
				if sig {
					select {
					case <-n.leaderBlockArrive:
						// n.logger.Info("case1-2", "Name", n.name, "Round", round)
						n.startABAWithOpResult(round)
					}
				} else {
					n.logger.Info("BADopLeader!")
					ch := make(chan bool, 1)
					n.pathChange[round] = ch
					n.pathChange[round] <- true
					n.tryToNextRound(round)
				}
			}
		}
	} else {
		select {
		case <-n.canMoveNext:
			if _, ok := n.done[round][opLeader]; ok {
				n.logger.Info("case2-1", "Name", n.name, "Round", round)
				n.tryToCommitOPLeader(round)
				<-n.leaderBlockArrive
				n.tryToNextRound(round)
			} else {
				n.startABAProcess(round, opLeader)
				select {
				case <-n.noNeedABA:
					select {
					case <-n.leaderBlockArrive:
						// n.logger.Info("case1-2", "Name", n.name, "Round", round)
						n.startABAWithOpResult(round)
					}
				case sig := <-n.ABAReturnCH:
					if sig {
						select {
						case <-n.leaderBlockArrive:
							// n.logger.Info("case1-2", "Name", n.name, "Round", round)
							n.startABAWithOpResult(round)
						}
					} else {
						n.logger.Info("BADopLeader!")
						ch := make(chan bool, 1)
						n.pathChange[round] = ch
						n.pathChange[round] <- true
						n.tryToNextRound(round)
					}
				}
			}
		}
	}
}
*/

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

	if count >= n.quorumNum {

		n.logger.Info("Msg", "name", n.name, "CurRound", n.round, "MoveNum", count, "ProtocolFlag", n.protocolFlag[n.round])

		n.round++
		var roundType RoundMsg
		// simply add pe path
		if n.protocolFlag[n.round-1] == 1 {
			// after waiting round, step into pe path's grbc
			n.protocolFlag[n.round] = 2
			roundType.Round = n.round
			roundType.Type = 2
			n.RoundType <- roundType
		} else if n.protocolFlag[n.round-1] == 2 {
			// step into pe path's cbc
			n.protocolFlag[n.round] = 3
			roundType.Round = n.round
			roundType.Type = 3
			n.RoundType <- roundType
		} else if n.protocolFlag[n.round-1] == 3 {
			// pe path's loop
			n.protocolFlag[n.round] = 0
			roundType.Round = n.round
			roundType.Type = 0
			n.RoundType <- roundType
		} else if n.protocolFlag[n.round-1] == 0 {
			// pe path's loop
			length := len(n.pathChange[round])
			if length > 0 {
				for len(n.pathChange[round]) > 0 {
					<-n.pathChange[round]
				}
				n.protocolFlag[n.round] = 2
				roundType.Round = n.round
				roundType.Type = 2
				n.RoundType <- roundType
			} else {
				n.protocolFlag[n.round] = 0
				roundType.Round = n.round
				roundType.Type = 0
				n.RoundType <- roundType
			}
		}
		go func() {
			n.nextRound <- round + 1
		}()
		// go n.tryToNextRound(round + 1)
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
				ch := make(chan bool, 1)
				n.pathChange[round+1] = ch
				n.pathChange[round+1] <- true
				endTime := time.Now().UnixNano()
				n.commitTime = append(n.commitTime, endTime)
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

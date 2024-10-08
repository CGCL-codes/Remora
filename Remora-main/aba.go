package Remora

import (
	"encoding/binary"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/seafooler/sign_tools"
	"sync"
)

// ABA is the Binary Byzantine Agreement build from a common coin protocol.
type ABA struct {
	node *Node

	height uint64

	aLogger hclog.Logger

	// Current round
	round uint64

	// mapValue maps from the componentID to the value (i.e., height)
	mapValue map[uint8]int

	// Bval requests we accepted this round.
	binValues map[uint8]struct{}

	// sentBvals are the binary values this instance sent
	// historical sentBvals must also be maintained due to the asynchronous network
	sentBvals map[uint64][2]bool

	// recvOddBval is a mapping of the sender and the received odd value
	// historical Bvals must also be maintained due to the asynchronous network
	recvOddBval map[uint64]map[string]bool

	// recvEvenBval is a mapping of the sender and the received even value
	// historical Bvals must also be maintained due to the asynchronous network
	recvEvenBval map[uint64]map[string]bool

	// recvAux is a mapping of the sender and the received Aux value.
	recvAux map[string]uint8

	// recvParSig maintains the received partial signatures to reveal the coin
	recvParSig [][]byte

	// recvAux is a mapping of the sender and the received exitMessage value.
	exitMsgs map[string]int

	// hasSentExitMsg indicates if the replica has sent the ExitMsg
	hasSentExitMsg bool

	// indicate if aba is finished and exited
	done  bool
	print bool

	// output and estimated of the aba protocol. This can be either nil or a
	// boolean.
	output, estimated interface{}

	//cachedBvalMsgs and cachedAuxMsgs cache messages that are received by a node that is
	// in a later round.
	cachedBvalMsgs map[uint64][]*ABABvalRequestMsg
	cachedAuxMsgs  map[uint64][]*ABAAuxRequestMsg

	lock sync.Mutex
}

// PrepareComponent acts when run the ABA protocol
/*
type PrepareComponent struct {
	node *Node

	height int

	aLogger hclog.Logger

	candidateData map[uint8]int

	lock sync.Mutex
}
*/

// NewABA returns a new instance of the Binary Byzantine Agreement.
func NewABA(node *Node, height uint64) *ABA {
	aBA := &ABA{
		node:   node,
		height: height,
		aLogger: hclog.New(&hclog.LoggerOptions{
			Name:       "ABA",
			Output:     hclog.DefaultOutput,
			TimeFormat: "2006-01-02 15:04:05.000000",
			//Level:      hclog.Level(node.Config.LogLevel),
		}),
		round:          0,
		recvOddBval:    make(map[uint64]map[string]bool),
		recvEvenBval:   make(map[uint64]map[string]bool),
		recvAux:        make(map[string]uint8),
		exitMsgs:       make(map[string]int),
		sentBvals:      make(map[uint64][2]bool),
		mapValue:       make(map[uint8]int),
		binValues:      make(map[uint8]struct{}),
		cachedBvalMsgs: make(map[uint64][]*ABABvalRequestMsg),
		cachedAuxMsgs:  make(map[uint64][]*ABAAuxRequestMsg),
	}

	aBA.recvOddBval[aBA.round] = make(map[string]bool)
	aBA.recvEvenBval[aBA.round] = make(map[string]bool)

	return aBA
}

func (b *ABA) initialABA(height uint64) {
	if _, ok := b.recvOddBval[height]; !ok {
		b.recvOddBval[height] = make(map[string]bool)
	}
	if _, ok := b.recvEvenBval[height]; !ok {
		b.recvEvenBval[height] = make(map[string]bool)
	}

}

/*
func (pc *PrepareComponent) handleMessage(pm *PrepareMsg) {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	if _, ok := pc.candidateData[pm.BValue]; !ok {
		pc.candidateData[pm.BValue] = 0
	}
	pc.candidateData[pm.BValue] = pc.candidateData[pm.BValue] + 1
	if pc.candidateData[0]+pc.candidateData[1] == 2*pc.node.F+1 {
		if pc.candidateData[0] == 2*pc.node.F+1 {
			pc.node.CommitData <- CommitData{
				ComponentId:   0,
				PayLoadHashes: pm.PayLoadHashes,
				Height:        pm.Height,
				Sender:        pm.BlockSender,
			}
		} else if pc.candidateData[1] == 2*pc.node.F+1 {
			pc.node.abaMap[pm.Height].inputValue(pm.Height, pm.PayLoadHashes, 1, pm.BlockSender)
		} else {
			pc.node.abaMap[pm.Height].inputValue(pm.Height, pm.PayLoadHashes, 0, pm.BlockSender)
		}
	}
}
*/

// inputValue will set the given val as the initial value to be proposed in the
// Agreement.
func (b *ABA) inputValue(h int, cId uint8, dealer string, round uint64) error {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.aLogger.Info("!!!!!!!!!!!!!!!!!!!! ABA is launched !!!!!!!!!!!!!!!!!!!!", "replica", b.node.name,
		"height", h)

	// Make sure we are in the first round.
	if b.round != 0 || b.estimated != nil {
		return nil
	}
	b.estimated = cId
	if cId == 0 {
		// set the first value as true
		b.sentBvals[0] = [2]bool{true, false}
		b.mapValue[0] = h % h
	} else {
		// set the second value as true
		b.sentBvals[0] = [2]bool{false, true}
		b.mapValue[1] = h%h + 1
	}
	msg := ABABvalRequestMsg{
		Sender: b.node.name,
		Dealer: dealer,
		Height: round,
		Round:  b.round,
		BValue: cId,
	}
	return b.node.broadcast(ABABvalRequestMsgTag, msg)
}

// handleBvalRequest processes the received binary value and fills up the
// message queue if there are any messages that need to be broadcast.
func (b *ABA) handleBvalRequest(msg *ABABvalRequestMsg) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.aLogger.Debug("receive an bval msg", "replica", b.node.name, "cur_round", b.round,
		"msg.Round", msg.Round, "msg.BValue", msg.BValue, "msg.Sender", msg.Sender, "oddBval", b.recvOddBval,
		"evenBval", b.recvEvenBval, "aux", b.recvAux, "binValues", b.binValues)

	// Messages from later rounds will be qued and processed later.
	if msg.Round > b.round {
		b.aLogger.Debug("receive a bval msg from a future round", "replica", b.node.name, "cur_round", b.round,
			"msg.Round", msg.Round)
		b.cachedBvalMsgs[msg.Round] = append(b.cachedBvalMsgs[msg.Round], msg)
		return nil
	}

	// Need to update binValues and broadcast corresponding bvals even if receiving an obsolete message
	if msg.BValue == 1 {
		b.recvOddBval[msg.Round][msg.Sender] = true
	} else {
		b.recvEvenBval[msg.Round][msg.Sender] = true
	}
	lenBval := b.countBvals(msg.BValue, msg.Round)

	// When receiving input(b) messages from f + 1 nodes, if inputs(b) is not
	// been sent yet broadcast input(b) and handle the input ourselves.
	if lenBval == b.node.nodeNum-b.node.quorumNum+1 && !b.hasSentBval(msg.BValue, msg.Round) {
		sb := b.sentBvals[msg.Round]
		if msg.BValue == 0 {
			sb[0] = true
		} else {
			sb[1] = true
		}
		b.sentBvals[msg.Round] = sb
		m := ABABvalRequestMsg{
			Sender: b.node.name,
			Dealer: msg.Dealer,
			Round:  msg.Round,
			Height: msg.Height,
			BValue: msg.BValue,
		}
		if err := b.node.broadcast(ABABvalRequestMsgTag, m); err != nil {
			return err
		}
	}

	// No need to update binValues after receiving an obsolete message
	if msg.Round < b.round {
		b.aLogger.Debug("receive a bval msg from an older round", "replica", b.node.name, "cur_round", b.round,
			"msg.Round", msg.Round)
		return nil
	}

	// When receiving n bval(b) messages from 2f+1 nodes: inputs := inputs u {b}
	if lenBval == b.node.quorumNum {
		wasEmptyBinValues := len(b.binValues) == 0
		b.binValues[msg.BValue] = struct{}{}
		// If inputs > 0 broadcast output(b) and handle the output ourselfs.
		// Wait until binValues > 0, then broadcast AUX(b). The AUX(b) broadcast
		// may only occur once per round.
		if wasEmptyBinValues {
			parSig := sign_tools.SignTSPartial(b.node.tsPrivateKey, []byte(fmt.Sprint(b.round)))
			m := ABAAuxRequestMsg{
				Height: msg.Height,
				Sender: b.node.name,
				Dealer: msg.Dealer,
				Round:  b.round,
				BValue: msg.BValue,
				TSPar:  parSig,
			}
			if err := b.node.broadcast(ABAAuxRequestMsgTag, m); err != nil {
				return err
			}
		}
		b.tryOutputAgreement(msg.Height, msg.Dealer)
	}
	return nil
}

func (b *ABA) handleAuxRequest(msg *ABAAuxRequestMsg) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.aLogger.Debug("receive an aux msg", "replica", b.node.name, "cur_round", b.round,
		"msg.Round", msg.Round, "msg.BValue", msg.BValue, "msg.Sender", msg.Sender, "oddBval", b.recvOddBval,
		"evenBval", b.recvEvenBval, "aux", b.recvAux, "binValues", b.binValues)

	// Ignore messages from older rounds.
	if msg.Round < b.round {
		b.aLogger.Debug("receive an aux msg from an older round", "replica", b.node.name, "cur_round", b.round,
			"msg.Round", msg.Round)
		return nil
	}
	// Messages from later rounds will be qued and processed later.
	if msg.Round > b.round {
		b.aLogger.Debug("receive an aux msg from a future round", "replica", b.node.name, "cur_round", b.round,
			"msg.Round", msg.Round)
		b.cachedAuxMsgs[b.round] = append(b.cachedAuxMsgs[b.round], msg)
		return nil
	}

	b.recvAux[msg.Sender] = msg.BValue
	b.recvParSig = append(b.recvParSig, msg.TSPar)
	b.tryOutputAgreement(msg.Height, msg.Dealer)
	return nil
}

// tryOutputAgreement waits until at least (N - f) output messages received,
// once the (N - f) messages are received, make a common coin and uses it to
// compute the next decision estimate and output the optional decision value.
func (b *ABA) tryOutputAgreement(height uint64, dealer string) {
	if len(b.binValues) == 0 {
		return
	}
	// Wait longer till eventually receive (N - F) aux messages.
	lenOutputs, values := b.countAuxs()
	if lenOutputs < b.node.quorumNum {
		return
	}

	// figure out the coin
	parSigs := b.recvParSig[:b.node.quorumNum]
	intactSig := sign_tools.AssembleIntactTSPartial(parSigs, b.node.tsPublicKey,
		[]byte(fmt.Sprint(b.round)), b.node.quorumNum, b.node.nodeNum)
	data := binary.BigEndian.Uint64(intactSig)
	coin := uint8(data % 2)
	b.aLogger.Debug("assemble the data and reveal the coin", "replica", b.node.name, "round", b.round, "height", b.height,
		"data", data, "coin", coin)

	if len(values) != 1 {
		if coin == values[0] {
			b.estimated = values[0]
		} else {
			b.estimated = values[1]
		}
	} else {
		b.estimated = values[0]
		// Output can be set only once.
		if b.output == nil && values[0]%2 == coin {
			b.output = values[0]
			b.aLogger.Info("output the agreed value", "replica", b.node.name, "value", values[0],
				"round", b.round, "msg.Height", height)
			b.hasSentExitMsg = true

			msg := ABAExitMsg{
				Height: height,
				Sender: b.node.name,
				Dealer: dealer,
				Value:  b.mapValue[values[0]], // Todo: fix it
			}
			if err := b.node.broadcast(ABAExitMsgTag, msg); err != nil {
				b.aLogger.Error(err.Error())
			}
		}
	}

	// Start the next round.
	b.aLogger.Debug("advancing to the next round after receiving aux messages", "replica", b.node.name,
		"next_round", b.round+1, "aux_msg_count", lenOutputs)
	b.advanceRound()

	estimated := b.estimated.(uint8)
	if estimated == 0 {
		b.sentBvals[b.round] = [2]bool{true, false}
	} else {
		b.sentBvals[b.round] = [2]bool{false, true}
	}

	msg := ABABvalRequestMsg{
		Sender: b.node.name,
		Dealer: dealer,
		// remember to check it
		Height: height,
		Round:  b.round,
		BValue: estimated,
	}
	if err := b.node.broadcast(ABABvalRequestMsgTag, msg); err != nil {
		b.aLogger.Error(err.Error(), "replica", b.node.name)
	}

	// process the cached messages for the next round.
	if cachedBvalMsgs, ok := b.cachedBvalMsgs[b.round]; ok {
		for _, cm := range cachedBvalMsgs {
			go func(m *ABABvalRequestMsg) {
				b.handleBvalRequest(m)
			}(cm)
		}
	}
	delete(b.cachedBvalMsgs, b.round)

	if cachedAuxMsgs, ok := b.cachedAuxMsgs[b.round]; ok {
		for _, cm := range cachedAuxMsgs {
			go func(m *ABAAuxRequestMsg) {
				b.handleAuxRequest(m)
			}(cm)
		}
	}
	delete(b.cachedAuxMsgs, b.round)
}

// countBvals counts all the received Bval inputs matching b.
// this function must be called in a mutex-protected env
func (b *ABA) countBvals(e uint8, round uint64) int {
	var toCheckBval map[string]bool
	if e == 1 {
		toCheckBval = b.recvOddBval[round]
	} else {
		toCheckBval = b.recvEvenBval[round]
	}

	return len(toCheckBval)
}

// hasSentBval return true if we already sent out the given value.
func (b *ABA) hasSentBval(e uint8, round uint64) bool {
	sb := b.sentBvals[round]
	if e%2 == 0 {
		return sb[0]
	} else {
		return sb[1]
	}
}

// advanceRound will reset all the values that are bound to a round and increments
// the round value by 1.
func (b *ABA) advanceRound() {
	b.binValues = make(map[uint8]struct{})
	b.recvAux = make(map[string]uint8)
	b.recvParSig = [][]byte{}
	b.round++
	b.recvOddBval[b.round] = make(map[string]bool)
	b.recvEvenBval[b.round] = make(map[string]bool)
}

func (b *ABA) handleExitMessage(msg *ABAExitMsg) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.exitMsgs[msg.Sender] = msg.Value
	lenEM := b.countExitMessages(msg.Value)
	if lenEM == b.node.nodeNum-b.node.quorumNum+1 && !b.hasSentExitMsg {
		b.hasSentExitMsg = true
		m := ABAExitMsg{
			Round:  msg.Round,
			Sender: b.node.name,
			Dealer: msg.Dealer,
			Value:  msg.Value,
		}
		if err := b.node.broadcast(ABAExitMsgTag, m); err != nil {
			b.aLogger.Error(err.Error(), "replica", b.node.name)
		}
	}

	if lenEM == b.node.quorumNum {
		if b.output == nil {
			b.aLogger.Info("output the agreed value after receiving 2f+1 exit msgs", "replica", b.node.name,
				"value", msg.Value, "round", b.round, "msg.Height", msg.Height)
			b.output = msg.Value
		}
		b.done = true
		b.aLogger.Info("Return from ABA", "nodeName", b.node.name, "output", b.output, "msg.Height", msg.Height)
		go b.node.UpdateABACondition(msg.Height)
		if b.output == 1 {
			b.node.ABAReturnCH <- true
		} else {
			b.node.ABAReturnCH <- false
		}
		/*
			go func() {
				b.node.ReadyData <- ReadyData{
					ComponentId:   1,
					PayLoadHashes: msg.PayLoadHashes,
					Height:        msg.Height,
					Sender:        msg.Dealer,
				}
			}()
		*/
	}
	return nil
}

// countExitMessages counts all the exitMessages matching v.
// this function must be called in a mutex-protected env
func (b *ABA) countExitMessages(e int) int {
	n := 0
	for _, val := range b.exitMsgs {
		if val == e {
			n++
		}
	}
	return n
}

// countAuxs returns the number of received (aux) messages, the corresponding
// values that where also in our inputs.
func (b *ABA) countAuxs() (int, []uint8) {
	valsMap := make(map[uint8]struct{})
	numQualifiedAux := 0
	for _, val := range b.recvAux {
		if _, ok := b.binValues[val]; ok {
			valsMap[val] = struct{}{}
			numQualifiedAux++
		}
	}

	var valsSet []uint8
	for val, _ := range valsMap {
		valsSet = append(valsSet, val)
	}

	return numQualifiedAux, valsSet
}

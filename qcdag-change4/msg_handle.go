package qcdag

import (
	"strconv"
	"time"
)

func (n *Node) HandleMsgLoop() {
	msgCh := n.trans.MsgChan()
	for {
		select {
		case msgWithSig := <-msgCh:
			if n.isFaulty {
				continue
			}
			switch msgAsserted := msgWithSig.Msg.(type) {
			case Block:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the block's signature", "round", msgAsserted.Round,
						"sender", msgAsserted.Sender)
					continue
				}
				go n.cbc.HandleBlockMsg(&msgAsserted)
			case Elect:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the echo's signature", "round", msgAsserted.Round,
						"sender", msgAsserted.Sender)
					continue
				}
				go n.handleElectMsg(&msgAsserted)
			case Ready:
				if !n.verifySigED25519(msgAsserted.ReadySender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the ready's signature", "round", msgAsserted.Round,
						"sender", msgAsserted.ReadySender, "blockSender", msgAsserted.BlockSender)
					continue
				}
				go n.cbc.handleReadyMsg(&msgAsserted)
			case Done:
				if !n.verifySigED25519(msgAsserted.DoneSender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the done's signature", "round", msgAsserted.Round,
						"sender", msgAsserted.DoneSender, "blockSender", msgAsserted.BlockSender)
					continue
				}
				/*
					if msgAsserted.Round > n.round {
						n.lock.Lock()
						n.storePendingDone(&msgAsserted)
						n.lock.Unlock()
						continue
					}
				*/
				n.lock.Lock()
				if n.protocolFlag[msgAsserted.Round] == 0 || n.protocolFlag[msgAsserted.Round] == 2 {
					n.lock.Unlock()
					go n.handleDoneMsg(&msgAsserted, true)
				} else {
					n.lock.Unlock()
					go n.handleDoneMsg(&msgAsserted, false)
				}
			case Vote:
				if !n.verifySigED25519(msgAsserted.VoteSender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the vote's signature", "round", msgAsserted.Round,
						"sender", msgAsserted.VoteSender, "blockSender", msgAsserted.BlockSender)
					continue
				}
				go n.cbc.HandleVoteMsg(&msgAsserted)
			case PrepareMsg:
				if !n.verifySigED25519(msgAsserted.PreSender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the echo's signature", "round", msgAsserted.Round,
						"sender", msgAsserted.PreSender)
					continue
				}
				go n.handlePrepareMsg(&msgAsserted)
			case HelpMsg:
				if !n.verifySigED25519(msgAsserted.HelpSender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the echo's signature", "round", msgAsserted.Round,
						"sender", msgAsserted.HelpSender)
					continue
				}
				go n.handleHelpMsg(&msgAsserted)
			case ABABvalRequestMsg:
				if !n.abaFinish[msgAsserted.Height] {
					go n.abaMap[msgAsserted.Height].handleBvalRequest(&msgAsserted)
				}
			case ABAAuxRequestMsg:
				if !n.abaFinish[msgAsserted.Height] {
					go n.abaMap[msgAsserted.Height].handleAuxRequest(&msgAsserted)
				}
			case ABAExitMsg:
				if !n.abaFinish[msgAsserted.Height] {
					go n.abaMap[msgAsserted.Height].handleExitMessage(&msgAsserted)
				}
			}
		}
	}
}

func (n *Node) handleCBCBlock(block *Block) {
	go n.tryToUpdateDAG(block)
}

func (n *Node) handleElectMsg(elect *Elect) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.storeElectMsg(elect)
	n.tryToElectLeader(elect.Round)
}

func (n *Node) handlePrepareMsg(msg *PrepareMsg) {
	helpMsg := HelpMsg{
		Round:       msg.Round,
		HelpSender:  n.name,
		BlockSender: msg.BlockSender,
		LBlockExist: 2,
	}
	if _, ok := n.done[msg.Round][msg.BlockSender]; ok {
		n.broadcastHelpMsg(helpMsg)
	} else if _, ok1 := n.dag[msg.Round][msg.BlockSender]; ok1 {
		helpMsg.LBlockExist = 1
		n.broadcastHelpMsg(helpMsg)
	} else {
		helpMsg.LBlockExist = 0
		n.broadcastHelpMsg(helpMsg)
	}
}

func (n *Node) handleHelpMsg(msg *HelpMsg) {
	n.lock.Lock()
	defer n.lock.Unlock()
	// n.logger.Info("????")
	if _, ok := n.savingHelpMsg[msg.Round]; !ok {
		n.savingHelpMsg[msg.Round] = make(map[string]*HelpMsg)
	}
	if _, ok := n.savingHelpMsg[msg.Round][msg.HelpSender]; !ok {
		n.savingHelpMsg[msg.Round][msg.HelpSender] = msg

		count := len(n.savingHelpMsg[msg.Round])
		if count == n.quorumNum {
			count2 := 0
			count1 := 0
			count0 := 0
			for _, helpInside := range n.savingHelpMsg[msg.Round] {
				if helpInside.LBlockExist == 2 {
					count2++
				} else if helpInside.LBlockExist == 1 {
					count1++
				} else {
					count0++
				}
			}
			if count2 > 0 {
				n.noNeedABA <- true
				n.logger.Info("Just wait. Grade = 2")
			} else if count1+count2 == count {
				n.noNeedABA <- true
				n.logger.Info("Just wait. ABA directly outputs 1.")
			} else if count1 > 0 {
				n.abaMap[msg.Round].inputValue(int(msg.Round), 1, msg.BlockSender, msg.Round)
			} else {
				n.logger.Info("ABA with input 0.", "nodeName", n.name)
				n.abaMap[msg.Round].inputValue(int(msg.Round), 0, msg.BlockSender, msg.Round)
			}
		}
	}
}

func (n *Node) handleDoneMsg(done *Done, flag bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	opLeader := "node" + strconv.Itoa(int(done.Round)%n.nodeNum)

	if flag {
		n.storeDone(done)
		if n.protocolFlag[done.Round] == 0 {
			if done.BlockSender == opLeader {
				n.leaderBlockArrive <- true
			}
			if len(n.done[done.Round]) >= n.quorumNum {
				if _, ok := n.doneEnoughSig[done.Round]; !ok {
					n.canMoveNext <- true
					n.doneEnoughSig[done.Round] = true
				}
			}
			n.checkOPFastPath(done.Round)
		} else if n.protocolFlag[done.Round] == 2 {
			n.tryToCommitLeader(done.Round)
			go n.tryToNextRound(done.Round)
		}
	}
}

func (n *Node) handlePendingDone(round uint64) {
	n.lock.Lock()
	if _, ok := n.pendingDone[round]; ok {
		for _, done := range n.pendingDone[round] {
			if n.protocolFlag[done.Round] == 0 || n.protocolFlag[done.Round] == 2 {
				go n.handleDoneMsg(done, true)
			} else {
				go n.handleDoneMsg(done, false)
			}
		}
		n.lock.Unlock()
	} else {
		n.lock.Unlock()
	}
}

func (n *Node) CBCOutputBlockLoop() {
	dataCh := n.cbc.ReturnBlockChan()
	for {
		select {
		case block := <-dataCh:
			n.logger.Debug("Block is received by from CBC", "node", n.name, "round",
				block.Round, "proposer", block.Sender)
			go n.handleCBCBlock(&block)
		}
	}
}

func (n *Node) DoneOutputLoop() {
	dataCh := n.cbc.ReturnDoneChan()
	for {
		select {
		case done := <-dataCh:
			n.lock.Lock()
			if n.protocolFlag[done.Round] == 0 || n.protocolFlag[done.Round] == 2 {
				n.lock.Unlock()
				go n.handleDoneMsg(&done, true)
			} else {
				n.lock.Unlock()
				go n.handleDoneMsg(&done, false)
			}
			// make sure every node can get 2f+1 done
			// go n.broadcastDone(done)
		}
	}
}

func (n *Node) RoundProcessLoop() {
	roundType := n.ReturnRoundType()
	for {
		select {
		case Msg := <-roundType:
			for round, Type := range Msg {
				if _, ok := n.abaMap[round]; !ok {
					n.abaMap[round] = NewABA(n, round)
					//n.abaMap[round].initialABA(round)
				}
				if Type == 0 {
					n.timer.Reset(100 * time.Millisecond)
					for len(n.opPathSig) > 0 {
						<-n.opPathSig
					}
					go func(t *time.Timer, ch chan uint64) {
						// n.logger.Info("CurRoundMsg", "Name", n.name, "Round", round)
						select {
						case <-t.C:
							// n.logger.Info("OutOfTime", "name", n.name, "Round", round)
							n.checkConditionWhileTimerExpire(round)
						case <-ch:
							n.lock.Lock()
							n.tryToCommitOPLeader(round)
							n.lock.Unlock()
							<-n.canMoveNext
							<-n.leaderBlockArrive
							go n.tryToNextRound(round)
						}
					}(n.timer, n.opPathSig)
				}
			}
		}
	}
}

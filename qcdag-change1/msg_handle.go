package qcdag1

func (n *Node) HandleMsgLoop() {
	msgCh := n.trans.MsgChan()
	for {
		select {
		case msgWithSig := <-msgCh:
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
				if msgAsserted.Round > n.round {
					n.lock.Lock()
					n.storePendingDone(&msgAsserted)
					n.lock.Unlock()
					continue
				}
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
			}
		}
	}
}

/*
func (n *Node) handleCBCGrade1Block(block *Block) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.storeGrade1Blocks(block)
	go n.tryToUpdateDAG(block)
}
*/

func (n *Node) handleCBCBlock(block *Block) {
	go n.tryToUpdateDAG(block)
}

func (n *Node) handleElectMsg(elect *Elect) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.storeElectMsg(elect)
	//temp_change
	n.tryToElectLeader(elect.Round)
}

func (n *Node) handleDoneMsg(done *Done, flag bool) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if flag {
		n.storeDone(done)
		/*
			if _, ok := n.grade1Blocks[done.Round]; !ok {
				n.grade1Blocks[done.Round] = make(map[string]*Block)
			}
			if _, ok := n.grade1Blocks[done.Round][done.BlockSender]; ok {
				tempBlock := n.grade1Blocks[done.Round][done.BlockSender]
				go n.tryToUpdateDAG(tempBlock)
			}
		*/
		//n.checkOPFastPath(done.Round)
		if n.protocolFlag[done.Round] == 0 {
			/*
				go func(t *time.Timer, doneMsg *Done, ch chan bool, round uint64) {
					select {
					case <-t.C:
					case <-ch:
						n.tryToCommitOPLeader(round)
					}
				}(n.timer, done, n.opPathSig, done.Round)
			*/
			n.tryToCommitOPLeader(done.Round)
		} else if n.protocolFlag[done.Round] == 2 {
			n.tryToCommitLeader(done.Round)
		}
		go n.tryToNextRound(done.Round)
	}
	//difference
	//n.tryToCommitOPLeader(done.Round)
	//n.tryToCommitLeader(done.Round)
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
			//difference
			/*
				n.lock.Lock()
				if n.protocolFlag[block.Round] == 1 || n.protocolFlag[block.Round] == 3 || n.protocolFlag[block.Round] == 4 {
					n.lock.Unlock()
					go n.handleCBCBlock(&block)
				} else {
					n.lock.Unlock()
					go n.handleCBCGrade1Block(&block)
				}
			*/
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
			go n.broadcastDone(done)
		}
	}
}

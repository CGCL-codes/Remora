package fork1

func (n *Node) HandleMsgLoop() {
	msgCh := n.trans.MsgChan()
	for {
		select {
		case msgWithSig := <-msgCh:
			switch msgAsserted := msgWithSig.Msg.(type) {
			case Vote:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the vote's signature", "view", msgAsserted.BlockView,
						"height", msgAsserted.BlockHeight, "sender", msgAsserted.Sender)
					continue
				}
				go n.handleVoteMsg(&msgAsserted)
			case Block:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the block's signature", "view", msgAsserted.View,
						"height", msgAsserted.Height, "sender", msgAsserted.Sender)
					continue
				}
				go n.handleBlockMsg(&msgAsserted)
			case Done:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the Done's signature", "view", msgAsserted.View,
						 "sender", msgAsserted.Sender)
					continue
				}
				go n.handleDoneMsg(&msgAsserted)
			case Finish:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the Finish's signature", "view", msgAsserted.View,
						"sender", msgAsserted.Sender)
					continue
				}
				go n.handleFinishMsg(&msgAsserted)
			case ViewChange:
				if !n.verifySigED25519(msgAsserted.Sender, msgWithSig.Msg, msgWithSig.Sig) {
					n.logger.Error("fail to verify the ViewChange's signature", "view", msgAsserted.View,
						"sender", msgAsserted.Sender)
					continue
				}
				go n.handleViewChangeMsg(&msgAsserted)
			}
		}
	}
}

func (n *Node) handleVoteMsg(vote *Vote) {
	if vote.BlockView > n.pbStop {
		n.storeVoteMsg(vote)
		n.checkIfQuorumVote(vote.BlockView, vote.BlockHeight)
	}
}

func (n *Node) handleBlockMsg(block *Block) {
	if !n.validateBlock(block) {
		return
	}
	// to avoid stuck, we will store all blocks
	n.storeBlockMsg(block)
	// nodes will not vote for slow blocks
	if block.View > n.pbStop {
		n.sendVote(block)
	}
}

func (n *Node) handleDoneMsg(done *Done) {
	n.storeDoneMsg(done)
	n.checkIfQuorumDone(done.View)
	// when receive Done, node will try to commit blocks
	n.lock.Lock()
	n.tryCommitBlock(done.View)
	n.lock.Unlock()
}

func (n *Node) handleFinishMsg(finish *Finish) {
	n.storeFinishMsg(finish)
	n.checkIfEnoughFinish(finish.View)
}

func (n *Node) handleViewChangeMsg(viewChange *ViewChange) {
	n.storeViewChangeMsg(viewChange)
	n.checkIfQuorumViewChange(viewChange.View)
}
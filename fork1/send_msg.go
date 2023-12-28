package fork1

import (
	"Remora/conn"
	"Remora/sign"
	"strconv"
)

func (n *Node) broadcastBlock1(view uint64) {
	// select highest QC of last view
	v, h, qc := n.selectHighestQC(view - 1)
	//此处可能还没有收到区块，还需改进
	//此处可能还不知道上一个view的leader
	previousBlock := n.candidateChain[v][n.leader[v]][h]
	hash, err := previousBlock.getHash()
	if err != nil {
		panic(err)
	}
	block1 := n.NewBlock(view, 0, hash, qc)
	// directly stores the block1
	n.storeBlockMsg(block1)
	err = n.broadcast(ProposalTag, block1)
	if err != nil {
		panic(err)
	}
}

func (n *Node) broadcastBlock2(qc []byte, view uint64) {
	// block2 chained to the node's own block1
	block1 := n.candidateChain[view][n.name][0]
	hash, err := block1.getHash()
	if err != nil {
		panic(err)
	}
	block2 := n.NewBlock(view, 1, hash, qc)
	err = n.broadcast(ProposalTag, block2)
	if err != nil {
		panic(err)
	}
}

// only send the vote to the proposer
func (n *Node) sendVote(block *Block) {
	hash, err := block.getHash()
	if err != nil {
		panic(err)
	}
	// node generates the partial threshold signature for the block hash
	partialSig := sign.SignTSPartial(n.tsPrivateKey, hash)
	vote := Vote{
		Sender:      n.name,
		BlockHash:   hash,
		BlockHeight: block.Height,
		BlockView:   block.View,
		PartialSig:  partialSig,
	}
	err = n.send(VoteTag, vote, block.Sender)
	if err != nil {
		panic(err)
	}
}

func (n *Node) broadcastDone(qc []byte, view uint64) {
	done := Done{
		Sender: n.name,
		View:   view,
		QC:     qc,
	}
	err := n.broadcast(DoneTag, done)
	if err != nil {
		panic(err)
	}
}

func (n *Node) broadcastFinish(view uint64) {
	data, err := encode(view)
	if err != nil {
		panic(err)
	}
	// node generates the partial threshold signature for view number
	partialSig := sign.SignTSPartial(n.tsPrivateKey, data)
	finish := Finish{
		Sender:     n.name,
		View:       view,
		PartialSig: partialSig,
	}
	err = n.broadcast(FinishTag, finish)
	if err != nil {
		panic(err)
	}
}

func (n *Node) broadcastViewChange(view uint64) {
	v, h, qc := n.selectHighestQC(view)
	qcSender := n.leader[v]
	viewChange := ViewChange{
		Sender:    n.name,
		View:      view,
		HighestQC: qc,
		QCHeight:  h,
		QCView:    v,
		QCSender:  qcSender,
	}
	err := n.broadcast(ViewChangeTag, viewChange)
	if err != nil {
		panic(err)
	}
}

// send message to all nodes
func (n *Node) broadcast(msgType uint8, msg interface{}) error {
	msgAsBytes, err := encode(msg)
	if err != nil {
		return err
	}
	sig := sign.SignEd25519(n.privateKey, msgAsBytes)
	for addrWithPort := range n.clusterAddrWithPorts {
		netConn, err := n.trans.GetConn(addrWithPort)
		if err != nil {
			return err
		}
		if err = conn.SendMsg(netConn, msgType, msg, sig); err != nil {
			return err
		}

		if err = n.trans.ReturnConn(netConn); err != nil {
			return err
		}
	}
	return nil
}

// only send message to one node
func (n *Node) send(msgType uint8, msg interface{}, target string) error {
	msgAsBytes, err := encode(msg)
	if err != nil {
		return err
	}
	sig := sign.SignEd25519(n.privateKey, msgAsBytes)
	addr := n.clusterAddr[target]
	port := n.clusterPort[target]
	addWithPort := addr + ":" + strconv.Itoa(port)
	netConn, err := n.trans.GetConn(addWithPort)
	if err != nil {
		return err
	}
	if err = conn.SendMsg(netConn, msgType, msg, sig); err != nil {
		return err
	}
	if err = n.trans.ReturnConn(netConn); err != nil {
		return err
	}
	return nil
}

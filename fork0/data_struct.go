package fork0

import "sync"

type Block struct {
	Sender       string
	Height       uint64 // Height = 0 or 1
	View         uint64
	PreviousHash []byte
	Txs          [][]byte
	QC           []byte // previous block's QC
	TC           [][]byte // contain 2f+1 viewChange's QC in last view
}

// Chain stores blocks which are committed
type Chain struct {
	lock      sync.RWMutex
	blocks    map[uint64]*Block // map chain's height to Block
	view      uint64 // the highest block's view
	height    uint64 // the highest block's height (0 or 1)
}

type Vote struct {
	Sender      string
	BlockHash   []byte
	BlockHeight uint64
	BlockView   uint64
	PartialSig  []byte
}

type Done struct {
	Sender    string
	View      uint64
	QC        []byte
}

type Finish struct {
	Sender      string
	View        uint64
	PartialSig  []byte
}

type ViewChange struct {
	Sender      string
	View        uint64
	HighestQC   []byte
	QCHeight    uint64
	QCView      uint64 // the view this QC is generated
	QCSender    string // the node generates this QC
}


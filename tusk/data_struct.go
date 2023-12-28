package tusk

type Block struct {
	Sender        string
	Round         uint64
	PreviousHash  map[string][]byte // at least 2f+1 block in last round, map from sender to hash
	Txs           [][]byte
	TimeStamp     int64
}

// Chain stores blocks which are committed
type Chain struct {
	round         uint64 // the max round of the leader that are committed
	blocks        map[string]*Block //map from hash to the block
}

type Elect struct {
	Sender        string
	Round         uint64
	PartialSig    []byte
}



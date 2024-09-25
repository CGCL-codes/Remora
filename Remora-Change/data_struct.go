package RemoraC

type Block struct {
	Sender       string
	Round        uint64
	PreviousHash map[string][]byte // at least 2f+1 block in last round, map from sender to hash
	Txs          [][]byte
	TimeStamp    int64
}

// Chain stores blocks which are committed
type Chain struct {
	round  uint64            // the max round of the leader that are committed
	blocks map[string]*Block //map from hash to the block
}

// vote for blocks
type Vote struct {
	VoteSender  string
	BlockSender string
	Round       uint64
}

// the vote for cbc-output-blocks in round % 2 = 1
type Ready struct {
	ReadySender string
	BlockSender string
	Round       uint64
	Hash        []byte // the block hash
	PartialSig  []byte
}

type Done struct {
	DoneSender  string
	BlockSender string // the node who send the block corresponding with the done
	Done        [][]byte
	Hash        []byte
	Round       uint64
}

type PrepareMsg struct {
	Round       uint64
	BlockSender string
	PreSender   string
	Val         int
}

type HelpMsg struct {
	Round       uint64
	HelpSender  string
	BlockSender string
	LBlockExist int // grade 0, 1, 2
}

// to elect a leader
type Elect struct {
	Sender     string
	Round      uint64
	PartialSig []byte
}

// ABABvalRequestMsg holds the input value of the binary input.
type ABABvalRequestMsg struct {
	Height uint64
	Round  uint64
	Sender string
	Dealer string
	BValue uint8
}

// ABAAuxRequestMsg holds the output value.
type ABAAuxRequestMsg struct {
	Height uint64
	Sender string
	Dealer string
	Round  uint64
	BValue uint8
	TSPar  []byte
}

// ABAExitMsg indicates that a replica has decided
type ABAExitMsg struct {
	Height uint64
	Round  uint64
	Sender string
	Dealer string
	Value  int
}

// RoundMsg presents round's status
type RoundMsg struct {
	Type  int
	Round uint64
}

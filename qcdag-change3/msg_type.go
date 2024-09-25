package qcdag3

import "reflect"

const (
	ProposalTag uint8 = iota
	VoteTag
	ElectTag
	ReadyTag
	DoneTag
	PrepareMsgTag
	HelpMsgTag
	ABABvalRequestMsgTag
	ABAExitMsgTag
	ABAAuxRequestMsgTag
)

var proposal Block
var vote Vote
var elect Elect
var ready Ready
var done Done
var pre PrepareMsg
var heLp HelpMsg
var ababrMsg ABABvalRequestMsg
var abaarMsg ABAAuxRequestMsg
var abaexMsg ABAExitMsg

var reflectedTypesMap = map[uint8]reflect.Type{
	ProposalTag:          reflect.TypeOf(proposal),
	VoteTag:              reflect.TypeOf(vote),
	ElectTag:             reflect.TypeOf(elect),
	ReadyTag:             reflect.TypeOf(ready),
	DoneTag:              reflect.TypeOf(done),
	PrepareMsgTag:        reflect.TypeOf(pre),
	HelpMsgTag:           reflect.TypeOf(heLp),
	ABABvalRequestMsgTag: reflect.TypeOf(ababrMsg),
	ABAAuxRequestMsgTag:  reflect.TypeOf(abaarMsg),
	ABAExitMsgTag:        reflect.TypeOf(abaexMsg),
}

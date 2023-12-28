package fork1

import "reflect"

const (
	ProposalTag uint8 = iota
	VoteTag
	DoneTag
	FinishTag
	ViewChangeTag
)

var proposal Block
var vote Vote
var done Done
var finish Finish
var viewChange ViewChange

var reflectedTypesMap = map[uint8]reflect.Type{
	ProposalTag:   reflect.TypeOf(proposal),
	VoteTag:       reflect.TypeOf(vote),
	DoneTag:       reflect.TypeOf(done),
	FinishTag:     reflect.TypeOf(finish),
	ViewChangeTag: reflect.TypeOf(viewChange),
}

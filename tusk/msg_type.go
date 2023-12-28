package tusk

import (
	"Remora/rbc"
	"reflect"
)

const (
	ElectTag uint8 = iota
	RBCValTag
	RBCEchoTag
	RBCReadyTag
)

var elect Elect
var valMsg rbc.VALMsg
var echoMsg rbc.ECHOMsg
var readyMsg rbc.READYMsg

var reflectedTypesMap = map[uint8]reflect.Type{
	ElectTag:    reflect.TypeOf(elect),
	RBCValTag:   reflect.TypeOf(valMsg),
	RBCEchoTag:  reflect.TypeOf(echoMsg),
	RBCReadyTag: reflect.TypeOf(readyMsg),
}

var rbcMsgType = map[string]uint8{
	"VAL":   RBCValTag,
	"ECHO":  RBCEchoTag,
	"READY": RBCReadyTag,
}

package main

import (
	"Remora/Remora-Change"
	"Remora/Remora-main"
	"Remora/config"
	"Remora/fork1"
	"Remora/qcdag"
	"Remora/tusk"
	"errors"
	"fmt"
	"time"
)

var conf *config.Config
var err error

func init() {
	conf, err = config.LoadConfig("", "config")
	if err != nil {
		panic(err)
	}
}

func main() {
	if conf.Protocol == "fork1" {
		startForkBFT1()
	} else if conf.Protocol == "qcdag" {
		startQCDAG()
	} else if conf.Protocol == "tusk" {
		startTusk()
	} else if conf.Protocol == "Remora" {
		startRemora()
	} else if conf.Protocol == "RemoraC" {
		startRemoraC()
	} else {
		panic(errors.New("the protocol is unknown"))
	}
}

func startForkBFT1() {
	node := fork1.NewNode(conf)
	if err = node.StartP2PListen(); err != nil {
		panic(err)
	}
	// wait for each node to start
	time.Sleep(time.Second * 10)
	if err = node.EstablishP2PConns(); err != nil {
		panic(err)
	}
	if !node.IsFaultyNode() {
		fmt.Println("node starts the ForkBFT1!")
		go node.RunLoop()
		node.HandleMsgLoop()
	}
}

func startQCDAG() {
	node := qcdag.NewNode(conf)
	if err = node.StartP2PListen(); err != nil {
		panic(err)
	}
	// wait for each node to start
	time.Sleep(time.Second * 25)
	if err = node.EstablishP2PConns(); err != nil {
		panic(err)
	}
	node.InitCBC(conf)
	fmt.Println("node starts the QCDAG!")
	go node.RunLoop()
	go node.HandleMsgLoop()
	go node.DoneOutputLoop()
	node.CBCOutputBlockLoop()
}

func startRemora() {
	node := Remora.NewNode(conf)
	if err = node.StartP2PListen(); err != nil {
		panic(err)
	}
	// wait for each node to start
	time.Sleep(time.Second * 10)
	if err = node.EstablishP2PConns(); err != nil {
		panic(err)
	}
	node.InitCBC(conf)
	fmt.Println("node starts the Remora!")
	go node.RunLoop()
	go node.HandleMsgLoop()
	go node.RoundProcessLoop()
	go node.DoneOutputLoop()
	node.CBCOutputBlockLoop()

}

func startRemoraC() {
	node := RemoraC.NewNode(conf)
	node.InitialRoundProcessChannel()
	if err = node.StartP2PListen(); err != nil {
		panic(err)
	}
	// wait for each node to start
	time.Sleep(time.Second * 25)
	if err = node.EstablishP2PConns(); err != nil {
		panic(err)
	}
	node.InitCBC(conf)
	fmt.Println("node starts the RemoraC!")
	go node.RunLoop()
	go node.HandleMsgLoop()
	go node.RoundProcessLoop()
	go node.DoneOutputLoop()
	node.CBCOutputBlockLoop()

}

func startTusk() {
	node := tusk.NewNode(conf)
	if err = node.StartP2PListen(); err != nil {
		panic(err)
	}
	// wait for each node to start
	time.Sleep(time.Second * 25)
	if err = node.EstablishP2PConns(); err != nil {
		panic(err)
	}
	node.InitRBC(conf)
	fmt.Println("node starts the Tusk!")
	go node.RunLoop()
	go node.HandleMsgLoop()
	node.ConstructedBlockLoop()
}

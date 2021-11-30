package ecc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"time"
)

var (
	NETWORKMAGIC        = []byte("f9beb4d9")
	TESTNETNETWORKMAGIC = []byte("0b110907")
)

type NetworkEnvelope struct {
	command []byte
	payload []byte
	magic   []byte
}

func NewNetworkEnvelope(command []byte, payload []byte, testnet bool) (Ne *NetworkEnvelope) {
	Ne = new(NetworkEnvelope)
	Ne.command = command
	Ne.payload = payload
	if bool(testnet) {
		Ne.magic = TESTNETNETWORKMAGIC
	} else {
		Ne.magic = NETWORKMAGIC
	}
	return
}

func (Ne *NetworkEnvelope) Repr() string {
	return fmt.Sprintf("%s", "%x", Ne.command, Ne.payload)
}

func (Ne *NetworkEnvelope) parse(s []byte, testnet bool) *NetworkEnvelope {
	var expectedMagic []byte
	var byt bytes.Buffer
	byt.Write(s)
	magic, _ := byt.ReadBytes(4)
	if reflect.DeepEqual(magic, []byte("")) {
		panic(fmt.Errorf("IOError: %v", "Connection reset!"))
	}
	if bool(testnet) {
		expectedMagic = TESTNETNETWORKMAGIC
	} else {
		expectedMagic = NETWORKMAGIC
	}
	if string(magic) != string(expectedMagic) {
		panic(fmt.Errorf("magic is not right %s vs %x", magic, expectedMagic))
	}
	command, _ := byt.ReadBytes(12)
	command = []byte(strings.Trim(string(command), string([]byte("\u0000"))))
	x, _ := byt.ReadBytes(4)
	payloadLength := littleEndianToInt(x)
	checksum, _ := byt.ReadBytes(4)
	payload, _ := byt.ReadBytes(byte(payloadLength))
	calculatedChecksum := hash256(string(payload))[:4]
	if calculatedChecksum != string(checksum) {
		panic(fmt.Errorf("IOError: %v", "checksum does not match"))
	}
	return NewNetworkEnvelope(command, payload, testnet)
}

func (Ne *NetworkEnvelope) serialize() []byte {
	result := Ne.magic
	result = append(Ne.command, func(repeated []byte, n int) (result []byte) {
		for i := 0; i < n; i++ {
			result = append(result, repeated...)
		}
		return result
	}([]byte("\u0000"), 12-len(Ne.command))...)
	result = append(result, intToLittleEndian(len(Ne.payload), 4)...)
	result = append(result, hash256(string(Ne.payload))[:4]...)
	result = append(result, Ne.payload...)
	return result
}

func (Ne *NetworkEnvelope) stream() []byte {
	//"Returns a stream for parsing the payload"
	return Ne.payload
	//BytesIO(self.payload)
}

type VersionMessage struct {
	command []byte

	version          int
	services         int
	timestamp        interface{}
	receiverServices int
	receiverIp       []byte
	receiverPort     int
	senderServices   int
	senderIp         []byte
	senderPort       int
	nonce            interface{}
	userAgent        []byte
	latestBlock      int
	relay            bool
}

func NewVersionMessage(
	version int,
	services int,
	timestamp interface{},
	receiverServices int,
	receiverIp []byte,
	receiverPort int,
	senderServices int,
	senderIp []byte,
	senderPort int,
	nonce interface{},
	userAgent []byte,
	latestBlock int,
	relay bool,
) (Vm *VersionMessage) {
	Vm = new(VersionMessage)
	Vm.command = []byte("version")
	Vm.version = 70015
	Vm.services = 0
	Vm.timestamp = nil
	if &timestamp == nil {
		Vm.timestamp = int(float64(time.Now().UnixNano()) / 1000000000.0)
	} else {
		Vm.timestamp = timestamp
	}
	Vm.receiverServices = 0
	Vm.receiverIp = []byte("\u0000\u0000\u0000\u0000")
	Vm.receiverPort = 8333
	Vm.senderServices = 0
	Vm.senderIp = []byte("\u0000\u0000\u0000\u0000")
	Vm.senderPort = 8333
	Vm.nonce = nil
	if &nonce == nil {
		//Perhaps crypto/rand is better for security reasons
		Vm.nonce = intToLittleEndian((rand.Intn(0) + int(math.Pow(2, 64))), 8)
	} else {
		Vm.nonce = nonce
	}
	Vm.userAgent = []byte("/programmingbitcoin:0.1/")
	Vm.latestBlock = latestBlock
	Vm.relay = relay
	return
}

//not particularly sure about the 'ffff'
func (Vm *VersionMessage) serialize() []byte {
	result := intToLittleEndian(Vm.version, 4)
	result = append(result, intToLittleEndian(Vm.services, 8)...)
	result = append(result, intToLittleEndian(Vm.timestamp.(int), 8)...)
	result = append(result, intToLittleEndian(Vm.receiverServices, 8)...)
	result = append(result, func(repeated []byte, n int) (result []byte) {
		for i := 0; i < n; i++ {
			result = append(result, repeated...)
		}
		return result
	}([]byte("\u0000"), 10)...)
	result = append(result, []byte("ffff")...)
	result = append(result, Vm.receiverIp...)

	combined := make([]byte, 2)
	binary.BigEndian.PutUint64(combined, uint64(Vm.receiverPort)) //int to bytes
	result = append(result, combined...)
	result = append(result, intToLittleEndian(Vm.senderServices, 8)...)
	result = append(result, func(repeated []byte, n int) (result []byte) {
		for i := 0; i < n; i++ {
			result = append(result, repeated...)
		}
		return result
	}([]byte("\u0000"), 10)...)
	result = append(result, []byte("ffff")...)
	result = append(result, Vm.senderIp...)

	combined2 := make([]byte, 2)
	binary.BigEndian.PutUint64(combined2, uint64(Vm.senderPort)) //int to bytes
	result = append(result, combined2...)
	result = append(result, Vm.nonce.([]byte)...)
	result = append(result, encodeVarint(len(Vm.userAgent))...)
	result = append(result, Vm.userAgent...)
	result = append(result, intToLittleEndian(Vm.latestBlock, 4)...)
	if Vm.relay {
		result = append(result, []byte("\u0001")...)
	} else {
		result = append(result, []byte("\u0000")...)
	}
	return result
}

type VerAckMessage struct {
}

func NewVerAckMessage() (Vm *VerAckMessage) {
	Vm = new(VerAckMessage)
	//command = []byte("verack")
	return
}

func (Vm *VerAckMessage) parse(s []byte) *VerAckMessage {
	Vm = new(VerAckMessage)
	return NewVerAckMessage()
}

func (Vm *VerAckMessage) serialize() []byte {
	return []byte("")
}

type PingMessage struct {
	nonce []byte
}

func NewPingMessage(nonce []byte) (Pm *PingMessage) {
	Pm = new(PingMessage)
	Pm.nonce = nonce
	return
}

func (Pm *PingMessage) parse(s []byte) *PingMessage {
	var byt bytes.Buffer
	byt.Write(s)
	nonce, _ := byt.ReadBytes(8)
	return NewPingMessage(nonce)
}

func (Pm *PingMessage) serialize() []byte {
	return Pm.nonce
}

type PongMessage struct {
	nonce []byte
}

func NewPongMessage(nonce []byte) (Pm *PongMessage) {
	Pm = new(PongMessage)
	Pm.nonce = nonce
	return
}

func (Pm *PongMessage) parse(s []byte) *PongMessage {
	var byt bytes.Buffer
	byt.Write(s)
	nonce, _ := byt.ReadBytes(8)
	return NewPongMessage(nonce)
}

func (Pm *PongMessage) serialize() []byte {
	return Pm.nonce
}

type GetHeadersMessage struct {
	version    int
	numHashes  int
	startBlock []byte
	endBlock   []byte
}

func NewGetHeadersMessage(version int, numHashes int, startBlock []byte, endBlock []byte) (Gh *GetHeadersMessage) {
	Gh = new(GetHeadersMessage)
	Gh.version = version
	Gh.numHashes = numHashes
	if &startBlock == nil {
		panic(fmt.Errorf("RuntimeError: %v", "a start block is required"))
	}
	Gh.startBlock = startBlock
	if &endBlock == nil {
		Gh.endBlock = func(repeated []byte, n int) (result []byte) {
			for i := 0; i < n; i++ {
				result = append(result, repeated...)
			}
			return result
		}([]byte("\u0000"), 32)
	} else {
		Gh.endBlock = endBlock
	}
	return
}

func (Gh *GetHeadersMessage) serialize() []byte {
	result := intToLittleEndian(Gh.version, 4)
	result = append(result, encodeVarint(Gh.numHashes)...)
	result = append(result, Gh.startBlock[:len(Gh.startBlock)-1]...)
	result = append(result, Gh.endBlock[:len(Gh.startBlock)-1]...)
	return result
}

type HeadersMessage struct {
	blocks []*Block
}

func NewHeadersMessage(blocks []*Block) (Hm *HeadersMessage) {
	Hm = new(HeadersMessage)
	Hm.blocks = blocks
	return
}

func (Hm *HeadersMessage) parse(stream []byte) *HeadersMessage {
	numHeaders := readVarint(stream)
	var blocks []*Block
	for i := 0; i < int(numHeaders); i++ {
		B := new(Block)
		blocks = append(blocks, B.parse(stream))
		num_txs := readVarint(stream)
		if num_txs != 0 {
			panic(fmt.Errorf("RuntimeError: %v", "number of txs not 0"))
		}
	}
	return NewHeadersMessage(blocks)
}

type SimpleNode struct {
	testnet bool
	logging bool
	socket  interface{}
	stream  []byte
}

func NewSimpleNode(host int, port int, testnet bool, logging bool) (Sn *SimpleNode) {
	Sn = new(SimpleNode)
	testnet = false
	logging = false
	if &port == nil {
		if bool(testnet) {
			port = 18333
		} else {
			port = 8333
		}
	}
	Sn.testnet = testnet
	Sn.logging = logging
	Sn.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	Sn.socket.connect([2]int{host, port})
	Sn.stream = Sn.socket.makefile("rb", nil)
	return
}

func handshake(Sn *SimpleNode) {
	//Do a handshake with the other node.
	//Handshake is sending a version message and getting a verack back.'''
	version := new(VersionMessage)
	Sn.send(version)
	//Sn.waitFor(VerAckMessage)
}

func (Sn *SimpleNode) send(message *VersionMessage) {
	//"Send a message to the connected node"
	envelope := NewNetworkEnvelope(message.command, message.serialize(), Sn.testnet)
	if Sn.logging {
		fmt.Println("sending: %d", (envelope))
	}
	Sn.socket.sendall(envelope.serialize())
}

func (Sn *SimpleNode) read() *NetworkEnvelope {
	//"Read a message from the socket"
	ne := new(NetworkEnvelope)
	envelope := ne.parse(Sn.stream, Sn.testnet)
	if Sn.logging {
		fmt.Println("receiving: %d", (envelope))
	}
	return envelope
}

//some significant issues that need more pairs of eyes
/*
func (Sn *SimpleNode) waitFor(messageClasses *VerAckMessage) {
	//"Wait for one of the messages in the list"
	command := nil
	command_to_class := func() (d map[interface{}]interface{}) {
		d = make(map[interface{}]interface{})
		for _, m := range messageClasses {
			d[m.command] = m
		}
		return
	}()
	for !func() bool {
		_, ok := command_to_class[command]
		return ok
	}() {
		//envelope = Sn.read()
		command = envelope.command
		if command == VersionMessage.command {
			Sn.send(VerAckMessage())
		} else if command == PingMessage.command {
			Sn.send(PongMessage(envelope.payload))
		}
	}
	command_to_class[command].parse(envelope.stream())
}
*/

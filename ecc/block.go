package ecc

import (
	"bytes"
	"math"
)

type Block struct {
	version    int
	prevBlock  []byte
	merkleRoot []byte
	timestamp  int
	bits       []byte
	nonce      []byte
}

func NewBlock(version int, prevBlock []byte, merkleRoot []byte, timestamp int, bits []byte, nonce []byte) (B *Block) {
	B = new(Block)
	B.version = version
	B.prevBlock = prevBlock
	B.merkleRoot = merkleRoot
	B.timestamp = timestamp
	B.bits = bits
	B.nonce = nonce
	return
}

func (B *Block) parse(s []byte) *Block {
	var byt bytes.Buffer
	byt.Write(s)
	x, _ := byt.ReadBytes(4)
	version := littleEndianToInt(x)
	y, _ := byt.ReadBytes(32)
	prevBlock := reverse(string(y))
	z, _ := byt.ReadBytes(32)
	merkleRoot := reverse(string(z))
	a, _ := byt.ReadBytes(4)
	timestamp := littleEndianToInt(a)
	b, _ := byt.ReadBytes(4)
	bits := b
	c, _ := byt.ReadBytes(4)
	nonce := c
	return NewBlock(int(version), []byte(prevBlock), []byte(merkleRoot), int(timestamp), bits, nonce)
}

func (B *Block) serialize() []byte {
	result := intToLittleEndian(B.version, 4)
	result = append(result, B.prevBlock[:]...)
	result = append(result, B.merkleRoot[:]...)
	result = append(result, intToLittleEndian(B.timestamp, 4)...)
	result = append(result, B.bits...)
	result = append(result, B.nonce...)
	return result
}

func (B *Block) hash() string {
	s := B.serialize()
	sha := hash256(string(s))
	return sha[:]
}

func (B *Block) bip9() bool {
	return B.version>>29 == 1
}

func (B *Block) bip91() bool {
	return B.version>>4&1 == 1
}

func (B *Block) bip141() bool {
	return B.version>>1&1 == 1
}

func (B *Block) checkPow() bool {
	sha := hash256(string(B.serialize()))
	proof := littleEndianToInt([]byte(sha))
	return proof < B.target()
}

func (B *Block) difficulty() float64 {
	lowest := 65535 * math.Pow(256, 29-3)
	return float64(lowest) / float64(B.target())
}

func (B *Block) target() int64 {
	return bitsToTarget(B.bits)
}

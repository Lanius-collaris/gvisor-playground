package stack

var IPv4HeaderForUDP = [20]byte{
	0x45, 0, 0, 0,
	0, 0, 0, 0,
	64, 17, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
}

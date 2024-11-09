package dialers

import (
	"encoding/binary"
	"net"
)

func IsClientHello(b []byte) bool {
	if len(b) < 9 {
		return false
	}
	//content_type handshake
	if b[0] != 0x16 {
		return false
	}
	if b[1] < 3 {
		return false
	}
	//msg_type client_hello
	if b[5] != 1 {
		return false
	}
	return true
}
func FragTLS(record []byte, size uint16) []byte {
	buf := make([]byte, len(record)+5)
	copy(buf[:3], record[:3])
	binary.BigEndian.PutUint16(buf[3:], size)
	copy(buf[5:5+size], record[5:5+size])

	copy(buf[5+size:8+size], record[:3])
	t := binary.BigEndian.Uint16(record[3:])
	binary.BigEndian.PutUint16(buf[8+size:], t-size)
	copy(buf[10+size:], record[5+size:])
	return buf
}

type TLSFragConn struct {
	*net.TCPConn
	Size uint16
	Used bool
}

func (conn *TLSFragConn) Write(b []byte) (int, error) {
	c := conn.TCPConn
	if conn.Used {
		return c.Write(b)
	}
	if !IsClientHello(b) {
		return c.Write(b)
	}
	if uint16(len(b)) < 5+conn.Size {
		return c.Write(b)
	}
	return c.Write(FragTLS(b, conn.Size))
}

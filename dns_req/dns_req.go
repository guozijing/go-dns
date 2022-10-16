package dns_req

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)

type Header struct {
	ID              uint16
	Flag            uint16
	QuestionCount   uint16
	AnswerCount     uint16
	AuthorityCount  uint16
	AdditionalCount uint16
}

func (h *Header) SetFlag(qr, opcode, aa, tc, rd, ra, rcode uint16) {
	h.Flag = qr<<15 + opcode<<11 + aa<<10 + tc<<9 + rd<<8 + ra<<7 + rcode
}

type Query struct {
	QuestionType  uint16
	QuestionClass uint16
}

func ParseDN(dn string) []byte {
	var (
		buf      bytes.Buffer
		segments []string = strings.Split(dn, ".")
	)

	for _, seg := range segments {
		binary.Write(&buf, binary.BigEndian, byte(len(seg)))
		binary.Write(&buf, binary.BigEndian, []byte(seg))
	}
	buf.Write([]byte{0})
	return buf.Bytes()
}

func DigDN(dnsServerAddr, dn string) {
	header := &Header{}
	header.AnswerCount = 0
	header.ID = 0xFFFF
	header.AdditionalCount = 0
	header.SetFlag(0, 0, 0, 0, 0, 0, 0)
	header.AuthorityCount = 0
	header.QuestionCount = 1

	query := Query{
		QuestionClass: 1,
		QuestionType:  1,
	}

	var (
		conn net.Conn
		err  error
		buf  bytes.Buffer
	)
	binary.Write(&buf, binary.BigEndian, header)
	binary.Write(&buf, binary.BigEndian, ParseDN(dn))
	binary.Write(&buf, binary.BigEndian, query)

	if conn, err = net.Dial("udp", dnsServerAddr); err != nil {
		log.Fatalln("Dial error: ", err)
	}
	defer conn.Close()

	if _, err = conn.Write(buf.Bytes()); err != nil {
		log.Fatalln(err)
	}

	bufR := make([]byte, 1024)
	n, err := conn.Read(bufR)
	if err != nil {
		log.Fatalln(err)
	}
	bufR = bufR[:n]
	q, _, i := dnsResDecode(bufR)
	fmt.Println("Query: ", q)
	fmt.Println("Answers: ", i)
}

func dnsResDecode(buf []byte) (querys, answers, ips []string) {
	header := buf[:12]
	queryNum := uint16(header[4])<<8 + uint16(header[5])
	answerNum := uint16(header[6])<<8 + uint16(header[7])
	data := buf[12:]
	index := 0
	queryBytes := make([][]byte, queryNum)
	answerBytes := make([][]byte, answerNum)

	for i := 0; i < int(queryNum); i++ {
		start := index
		l := 0
		for {
			l = int(data[index])
			if l == 0 {
				break
			}
			index += 1 + l
		}
		index += 4
		queryBytes[i] = data[start : index+1]
		index += 1
	}
	if answerNum != 0 {
		for i := 0; i < int(answerNum); i++ {
			start := index
			nums := 2 + 2 + 2 + 4 + 2
			dataLenIndex := start + 2 + 2 + 2 + 4
			dataLen := int(uint16(data[dataLenIndex])<<8 + uint16(data[dataLenIndex+1]))
			index = start + nums - 1 + dataLen
			answerBytes[i] = data[start : index+1]
			index += 1
		}
	}

	querys = make([]string, queryNum)
	answers = make([]string, answerNum)
	for i, bytes := range queryBytes {
		querys[i] = getQuery(bytes)
	}

	for i, bytes := range answerBytes {
		answers[i] = getAnswer(bytes)
		if ip := getIP(bytes); ip != "" {
			ips = append(ips, ip)
		}
	}
	return querys, answers, ips
}

func getQuery(bytes []byte) string {
	return getDN(bytes)
}

func getAnswer(bytes []byte) string {
	typ := uint16(bytes[2])<<8 + uint16(bytes[3])
	datalenIndex := 2 + 2 + 2 + 4
	dataLen := int(uint16(bytes[datalenIndex])<<8 + uint16(bytes[datalenIndex+1]))
	address := bytes[datalenIndex+2 : datalenIndex+2+dataLen]
	if typ == 1 {
		return fmt.Sprintf("%d.%d.%d.%d", address[0],
			address[1], address[2], address[3])
	} else if typ == 5 {
		return getDN(bytes)
	}
	return ""
}

func getIP(bytes []byte) string {
	typ := uint16(bytes[2])<<8 + uint16(bytes[3])
	datalenIndex := 2 + 2 + 2 + 4
	dataLen := int(uint16(bytes[datalenIndex])<<8 + uint16(bytes[datalenIndex+1]))
	address := bytes[datalenIndex+2 : datalenIndex+2+dataLen]
	if typ == 1 {
		return fmt.Sprintf("%d.%d.%d.%d", address[0],
			address[1], address[2], address[3])
	}
	return ""
}

func getDN(bytes []byte) string {
	dn := ""
	index := 0
	l := 0
	for {
		if index >= len(bytes) {
			break
		}
		l = int(bytes[index])
		if l == 0 {
			break
		}
		if index+1+l > len(bytes) {
			dn += string(bytes[index+1:]) + "."
		} else {
			dn += string(bytes[index+1:index+l+1]) + "."
		}
		index += 1 + l
	}
	dn = strings.Trim(dn, ".")
	return dn
}

package gopcap

import (
	"bytes"
	"io"
	"time"
)

// checkMagicNum checks the first four bytes of a pcap file, searching for the magic number
// and checking the byte order. Returns three values: whether the file is a pcap file, whether
// the byte order needs flipping, and any error that was encountered. If error is returned,
// the other values are invalid.
func checkMagicNum(src io.Reader) (bool, bool, error) {
	// These magic numbers form the header of a pcap file.
	magic := []byte{0xa1, 0xb2, 0xc3, 0xd4}
	magicReverse := []byte{0xd4, 0xc3, 0xb2, 0xa1}

	buffer := make([]byte, 4)
	readCount, err := src.Read(buffer)

	if readCount != 4 {
		return false, false, ErrInsufficientLength
	}
	if (err != nil) && (err != io.EOF) {
		return false, false, err
	}

	if bytes.Compare(buffer, magic) == 0 {
		return true, false, nil
	} else if bytes.Compare(buffer, magicReverse) == 0 {
		return true, true, nil
	}

	return false, false, ErrNotAPcapFile
}

// parsePacket parses a full packet out of the pcap file. It returns an error if any problems were
// encountered.
func parsePacket(pkt *Packet, src io.Reader, flipped bool, linkType Link) error {
	err := populatePacketHeader(pkt, src, flipped)

	if err != nil {
		return err
	}

	data := make([]byte, pkt.IncludedLen)
	readlen, err := src.Read(data)
	if uint32(readlen) != pkt.IncludedLen {
		return ErrUnexpectedEOF
	}

	pkt.Data, err = parseLinkData(data, linkType)

	return err
}

// populateFileHeader reads the next 20 bytes out of the .pcap file and uses it to populate the
// PcapFile structure.
func populateFileHeader(file *PcapFile, src io.Reader, flipped bool) error {
	buffer := make([]byte, 20)
	readCount, err := src.Read(buffer)

	if err != nil {
		return err
	} else if readCount != 20 {
		return ErrInsufficientLength
	}

	// First two bytes are the major version number.
	file.MajorVersion = GetUint16(buffer[0:2], flipped)

	// Next two are the minor version number.
	file.MinorVersion = GetUint16(buffer[2:4], flipped)

	// GMT to local correction, in seconds east of UTC.
	file.TZCorrection = GetInt32(buffer[4:8], flipped)

	// Next is the number of significant figures in the timestamps. Almost always zero.
	file.SigFigs = GetUint32(buffer[8:12], flipped)

	// Now the maximum length of the captured packet data.
	file.MaxLen = GetUint32(buffer[12:16], flipped)

	// And the link type.
	file.LinkType = Link(GetUint32(buffer[16:20], flipped))

	return nil
}

// populatePacketHeader reads the next 16 bytes out of the file and builds it into a
// packet header.
func populatePacketHeader(packet *Packet, src io.Reader, flipped bool) error {
	buffer := make([]byte, 16)
	readCount, err := src.Read(buffer)

	if err != nil {
		return err
	} else if readCount != 16 {
		return ErrInsufficientLength
	}

	// First is a pair of fields that build up the timestamp.
	tsSeconds := GetUint32(buffer[0:4], flipped)
	tsMicros := GetUint32(buffer[4:8], flipped)
	packet.Timestamp = (time.Duration(tsSeconds) * time.Second) + (time.Duration(tsMicros) * time.Microsecond)

	// Next is the length of the data segment.
	packet.IncludedLen = GetUint32(buffer[8:12], flipped)

	// Then the original length of the packet.
	packet.ActualLen = GetUint32(buffer[12:16], flipped)

	return err
}

// parseLinkData takes the data buffer containing the full link-layer packet (or equivalent, e.g.
// Ethernet frame) and builds an appropriate in-memory representation.
func parseLinkData(data []byte, linkType Link) (LinkLayer, error) {
	var pkt LinkLayer

	switch linkType {
	case ETHERNET:
		if bytes.Equal(data, []byte{0, 0, 0, 0}) {
			return nil, ErrPacketSizeLimited
		}
		pkt = new(EthernetFrame)
	default:
		pkt = new(UnknownLink)
	}

	err := pkt.FromBytes(data)
	return pkt, err
}

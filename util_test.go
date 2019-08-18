package gopcap

import "testing"

func TestGetUint16(t *testing.T) {
	// Prepare some test byte arrays.
	in := [][]byte{
		[]byte{0x99, 0x12},
		[]byte{0xff, 0x01},
		[]byte{0x09, 0x0a},
	}

	outNotFlipped := []uint16{
		uint16(39186),
		uint16(65281),
		uint16(2314),
	}

	outFlipped := []uint16{
		uint16(4761),
		uint16(511),
		uint16(2569),
	}

	for i, input := range in {
		out1 := GetUint16(input, false)
		out2 := GetUint16(input, true)

		if out1 != outNotFlipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", outNotFlipped[i], out1)
		}

		if out2 != outFlipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", outFlipped[i], out2)
		}
	}
}

func TestGetUint32(t *testing.T) {
	// Prepare some test byte arrays.
	in := [][]byte{
		[]byte{0x99, 0x12, 0x66, 0x00},
		[]byte{0xff, 0x01, 0x08, 0xdd},
		[]byte{0x09, 0x0a, 0x12, 0x66},
	}

	outNotFlipped := []uint32{
		uint32(2568119808),
		uint32(4278257885),
		uint32(151655014),
	}

	outFlipped := []uint32{
		uint32(6689433),
		uint32(3708289535),
		uint32(1712458249),
	}

	for i, input := range in {
		out1 := GetUint32(input, false)
		out2 := GetUint32(input, true)

		if out1 != outNotFlipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", outNotFlipped[i], out1)
		}

		if out2 != outFlipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", outFlipped[i], out2)
		}
	}
}

func TestGetInt32(t *testing.T) {
	// Prepare some test byte arrays.
	in := [][]byte{
		[]byte{0x99, 0x12, 0x66, 0x00},
		[]byte{0xff, 0x01, 0x08, 0xdd},
		[]byte{0x09, 0x0a, 0x12, 0x66},
	}

	outNotFlipped := []int32{
		int32(-1726847488),
		int32(-16709411),
		int32(151655014),
	}

	outFlipped := []int32{
		int32(6689433),
		int32(-586677761),
		int32(1712458249),
	}

	for i, input := range in {
		out1 := GetInt32(input, false)
		out2 := GetInt32(input, true)

		if out1 != outNotFlipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", outNotFlipped[i], out1)
		}

		if out2 != outFlipped[i] {
			t.Errorf("Incorrect output: expected %v, got %v.", outFlipped[i], out2)
		}
	}
}

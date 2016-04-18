package libssh

import "testing"

func TestBuffer(t *testing.T) {
	testdata := []byte{1, 2, 3, 4, 5, 6, 8, 9, 0}
	buffer := NewBuffer()
	if buffer == nil {
		t.Fatal("unable to allocate buffer")
	}
	defer buffer.Free()
	err := buffer.AddData(testdata)
	if err != nil {
		t.Fatal(err)
	}
	read := buffer.ReadAll()
	if len(read) != len(testdata) {
		t.Fatalf("read length: %d, expected: %d", len(read), len(testdata))
	}
	for i := 0; i < len(read); i++ {
		if read[i] != testdata[i] {
			t.Errorf("byte[%d]: 0x%02x != 0x%02x", i, read[i], testdata[i])
		}
	}
}

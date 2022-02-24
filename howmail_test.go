package main

import (
	"context"
	"testing"
)

func TestSelfTest(t *testing.T) {
	dc := NewDNSClient("1.1.1.1:853")
	defer dc.Close()
	if err := selfTest(context.Background(), dc); err != nil {
		t.Errorf("Error in selfTest: %v", err)
	}
}

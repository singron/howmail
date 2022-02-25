package main

import (
	"context"
	"testing"

	"github.com/singron/howmail/dnsclient"
)

func TestSelfTest(t *testing.T) {
	dc := dnsclient.New("1.1.1.1:853")
	defer dc.Close()
	if err := selfTest(context.Background(), dc); err != nil {
		t.Errorf("Error in selfTest: %v", err)
	}
}

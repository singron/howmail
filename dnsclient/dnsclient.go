package dnsclient

import (
	"context"
	"errors"
	"io"
	"log"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// Client is a goroutine-safe way to make DNS requests.
type Client struct {
	addr string
	reqC chan *callReq
}

// New creates a new client that will dial addr. It returns
// immediately and will lazily create a connection.
func New(addr string) *Client {
	c := &Client{
		addr: addr,
		reqC: make(chan *callReq),
	}
	go c.run()
	return c
}

type callReq struct {
	msg *dns.Msg
	c   chan *callRes
}

type callRes struct {
	msg *dns.Msg
	err error
}

// Close releases internal resources. Concurrent calls to Call may panic.
func (c *Client) Close() {
	close(c.reqC)
}

func (c *Client) runRead(conn *dns.Conn, msgC chan<- *dns.Msg) {
	defer conn.Close()
	defer close(msgC)
	for {
		msg, err := conn.ReadMsg()
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from dns.Conn: %v", err)
			}
			break
		}
		msgC <- msg
	}
}

func (c *Client) run() {
	m := make(map[uint16]*callReq)
	var conn *dns.Conn
	var msgC chan *dns.Msg
	// Timers are pretty tricky to use. The docs on .Stop and .Reset aren't
	// complete. In particular, .Stop assumes it's not stopped and .Reset
	// assumes it is stopped. We carefully make sure we flip-flop the state in
	// this func.
	idleTimeout := time.NewTimer(0)
	if !idleTimeout.Stop() {
		<-idleTimeout.C
	}
	closeConn := func() {
		if conn != nil {
			conn.Close()
			conn = nil
			msgC = nil
			if len(m) == 0 {
				if !idleTimeout.Stop() {
					<-idleTimeout.C
				}
			}
		}
		for _, req := range m {
			req.c <- &callRes{err: errors.New("Connection closed during request")}
		}
		m = make(map[uint16]*callReq)
	}
	defer func() {
		closeConn()
	}()
loop:
	for {
		select {
		case <-idleTimeout.C:
			// closeConn assumes the timer is started if we are idle.
			idleTimeout.Reset(1 * time.Second)
			closeConn()
		case msg, ok := <-msgC:
			if !ok {
				closeConn()
				continue
			}
			req := m[msg.Id]
			if req != nil {
				req.c <- &callRes{msg: msg}
			}
			wasBusy := len(m) > 0
			delete(m, msg.Id)
			if wasBusy && len(m) == 0 {
				idleTimeout.Reset(10 * time.Second)
			}
		case req, ok := <-c.reqC:
			if !ok {
				break loop
			}
			if conn == nil {
				var err error
				msgC = make(chan *dns.Msg)
				conn, err = dns.DialWithTLS("tcp4", c.addr, nil)
				if err != nil {
					log.Printf("Error dialing dns: %v", err)
					req.c <- &callRes{err: err}
					continue
				}
				idleTimeout.Reset(10 * time.Second)
				go c.runRead(conn, msgC)
			}
			for m[req.msg.Id] != nil {
				req.msg.Id = dns.Id()
			}
			if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				log.Printf("Error setting write deadline: %v", err)
			}
			if err := conn.WriteMsg(req.msg); err != nil {
				closeConn()
				req.c <- &callRes{err: err}
				continue
			}
			if len(m) == 0 {
				// Were idle, but now not.
				if !idleTimeout.Stop() {
					<-idleTimeout.C
				}
			}
			m[req.msg.Id] = req
		}
	}
}

// Call sends a message to the DNS server and returns the response. It is safe
// to call from multiple goroutines as long as Client is open. It may retry
// internally.
func (c *Client) Call(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	tries := 0
	for {
		resC := make(chan *callRes, 1)
		req := &callReq{
			c:   resC,
			msg: msg,
		}
		select {
		case c.reqC <- req:
		case <-ctx.Done():
			syscall.Kill(syscall.Getpid(), syscall.SIGQUIT)
			time.Sleep(1 * time.Second)
			return nil, ctx.Err()
		}

		tries++
		select {
		case res := <-resC:
			if tries < 3 && res.err != nil {
				log.Printf("Retrying DNS error: %v", res.err)
				time.Sleep(100 * time.Duration(tries) * time.Millisecond)
				continue
			}
			return res.msg, res.err
		case <-ctx.Done():
			syscall.Kill(syscall.Getpid(), syscall.SIGQUIT)
			time.Sleep(1 * time.Second)
			return nil, ctx.Err()
		}
	}
}

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

var (
	portFlag = flag.Int("port", 8080, "port to listen on")
)

// DNSClient is a goroutine-safe way to make DNS requests.
type DNSClient struct {
	addr string
	reqC chan *callReq
}

// NewDNSClient creates a new client that will dial addr. It returns
// immediately and will lazily create a connection.
func NewDNSClient(addr string) *DNSClient {
	p := &DNSClient{
		addr: addr,
		reqC: make(chan *callReq),
	}
	go p.run()
	return p
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
func (p *DNSClient) Close() {
	close(p.reqC)
}

func (p *DNSClient) runRead(conn *dns.Conn, msgC chan<- *dns.Msg) {
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

func (p *DNSClient) run() {
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
		case req, ok := <-p.reqC:
			if !ok {
				break loop
			}
			if conn == nil {
				var err error
				msgC = make(chan *dns.Msg)
				conn, err = dns.DialWithTLS("tcp4", p.addr, nil)
				if err != nil {
					log.Printf("Error dialing dns: %v", err)
					req.c <- &callRes{err: err}
					continue
				}
				idleTimeout.Reset(10 * time.Second)
				go p.runRead(conn, msgC)
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
// to call from multiple goroutines as long as DNSClient is open. It may retry
// internally.
func (p *DNSClient) Call(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	tries := 0
	for {
		resC := make(chan *callRes, 1)
		req := &callReq{
			c:   resC,
			msg: msg,
		}
		select {
		case p.reqC <- req:
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

// QueryRes is the result of querying a domain.
type QueryRes struct {
	Err          string
	Domain       string
	MXs          []string
	HasGoogle    bool
	HasMicrosoft bool
	Raw          string
}

func query(ctx context.Context, dc *DNSClient, domain string) QueryRes {
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			Opcode:           dns.OpcodeQuery,
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain),
				Qtype:  dns.TypeMX,
				Qclass: dns.ClassINET,
			},
		},
	}
	qres := QueryRes{
		Domain: domain,
	}
	res, err := dc.Call(ctx, req)
	if err != nil {
		qres.Err = fmt.Sprintf("Error sending message to DNS server: %v", err)
		return qres
	}
	if res.Rcode != 0 {
		qres.Err = fmt.Sprintf("Failed rcode from DNS server: %v: %v", res.Rcode, dns.RcodeToString[res.Rcode])
	}

	qres.Raw = res.String()

	for _, a := range res.Answer {
		switch a := a.(type) {
		case *dns.MX:
			mx := strings.ToLower(a.Mx)
			if strings.HasSuffix(mx, ".googlemail.com.") || strings.HasSuffix(mx, ".google.com.") {
				qres.HasGoogle = true
			}
			if strings.HasSuffix(mx, ".outlook.com.") || strings.HasSuffix(mx, ".office365.us") {
				qres.HasMicrosoft = true
			}
		case *dns.CNAME:
		default:
			qres.Err = "malformed DNS MX record"
			return qres
		}
	}
	return qres
}

func selfTest(ctx context.Context, dc *DNSClient) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	qres := query(ctx, dc, "google.com")
	if qres.Err != "" {
		return fmt.Errorf("error querying for google.com: %v", qres.Err)
	}
	if !qres.HasGoogle {
		return fmt.Errorf("google.com: want HasGoogle, got !HasGoogle")
	}
	if qres.HasMicrosoft {
		return fmt.Errorf("google.com: want !HasMicrosoft, got HasMicrosoft")
	}

	qres = query(ctx, dc, "microsoft.com")
	if qres.Err != "" {
		return fmt.Errorf("error querying for google.com: %v", qres.Err)
	}
	if qres.HasGoogle {
		return fmt.Errorf("microsoft.com: want !HasGoogle, got HasGoogle")
	}
	if !qres.HasMicrosoft {
		return fmt.Errorf("microsoft.com: want HasMicrosoft, got !HasMicrosoft")
	}

	return nil
}

// Page is the passed to the tempate.
type Page struct {
	Domain  string
	Results []QueryRes
}

var tmpl = template.Must(template.New("tmpl").Parse(`
<!doctype html>
<title>howmail{{if .Domain}} | {{.Domain}}{{end}}</title>
<h1>howmail</h1>
<p>Query a domain to see information about its mail server.
<form action="" method="GET">
<input name="domain" value="{{.Domain}}" placeholder="google.com"></input>
</form>

{{range .Results}}
<h2>{{.Domain}}</h2>
{{if .Err}}
<p>Error: {{.Err}}
{{else if .Domain}}
<p>Google Workspace domain: {{ .HasGoogle }}
<p>Microsoft domain: {{ .HasMicrosoft }}
{{end}}
{{if .Raw}}
<p>DNS Packet:
<pre>
{{.Raw}}
</pre>
{{end}}
{{end}}
<p>
<a href="https://github.com/singron/howmail">source</a>
`))

func main() {
	flag.Parse()
	ctx := context.Background()
	dc := NewDNSClient("1.1.1.1:853")
	defer dc.Close()
	if err := selfTest(ctx, dc); err != nil {
		syscall.Kill(syscall.Getpid(), syscall.SIGQUIT)
		time.Sleep(1 * time.Second)
		log.Fatalf("Error in selfTest: %v", err)
	}
	log.Printf("selfTest success")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/html")

		if err := r.ParseForm(); err != nil {
			log.Printf("Error parsing form: %v", err)
			w.WriteHeader(400)
			fmt.Fprintf(w, "<!doctype html>\nBad request")
			return
		}
		domain := r.Form.Get("domain")
		var results []QueryRes
		if domain != "" {
			log.Printf("Request domain=%q", domain)
			results = append(results, query(ctx, dc, domain))
			etld, err := publicsuffix.EffectiveTLDPlusOne(domain)
			if err == nil && dns.Fqdn(etld) != dns.Fqdn(domain) {
				results = append(results, query(ctx, dc, etld))
			}
		}
		var buf bytes.Buffer
		page := Page{
			Domain:  domain,
			Results: results,
		}
		if err := tmpl.Execute(&buf, page); err != nil {
			log.Printf("Template error: %v", err)
			w.WriteHeader(500)
			fmt.Fprintf(w, "<!doctype html>\nServer error")
			return
		}
		if _, err := io.Copy(w, &buf); err != nil {
			log.Printf("Error writing response: %v", err)
		}
	})

	if err := http.ListenAndServe(fmt.Sprintf("[::1]:%d", *portFlag), nil); err != nil {
		log.Fatalf("Error in ListenAndServe: %v", err)
	}
}

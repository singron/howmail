package main

import (
	"bytes"
	"context"
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
	"github.com/singron/howmail/dnsclient"
	"golang.org/x/net/publicsuffix"
)

var (
	portFlag = flag.Int("port", 8080, "port to listen on")
)

// QueryRes is the result of querying a domain.
type QueryRes struct {
	Err          string
	Domain       string
	MXs          []string
	HasGoogle    bool
	HasMicrosoft bool
	Raw          string
}

func query(ctx context.Context, dc *dnsclient.Client, domain string) QueryRes {
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

func selfTest(ctx context.Context, dc *dnsclient.Client) error {
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
	dc := dnsclient.New("1.1.1.1:853")
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

package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type dnsHandler struct {
	logger *zap.Logger
}

func (s *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	msg := dns.Msg{}
	msg.SetReply(r)

	switch r.Question[0].Qtype {
	case dns.TypeA:
		domain := msg.Question[0].Name
		s.logger.Info("DNS A request", zap.String("from", w.RemoteAddr().String()), zap.String("domain", domain))

		// Make sure we resolve _something_ for an A record.
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.1.1.1"),
		})

		w.WriteMsg(&msg)

	case dns.TypeAAAA:
		domain := msg.Question[0].Name
		s.logger.Info("DNS AAAA request", zap.String("from", w.RemoteAddr().String()), zap.String("domain", domain))
	default:
		s.logger.Info("Unknown DNS request", zap.String("from", w.RemoteAddr().String()), zap.String("as_string", r.String()))
	}

}

// LogDNS logs DNS requests.
func LogDNS(logger *zap.Logger) error {
	handler := &dnsHandler{logger: logger}
	dnsServer := &dns.Server{
		Addr:    ":53",
		Net:     "udp",
		Handler: handler,
	}

	return dnsServer.ListenAndServe()
}

// GetRequestIP gets an http.request ip.
// From https://golangcode.com/get-the-request-ip-addr/
func GetRequestIP(r *http.Request) string {
	fip := r.Header.Get("X-FORWARDED-FOR")
	if fip != "" {
		return fip
	}
	return r.RemoteAddr
}

// LogHTTP logs HTTP requests.
func LogHTTP(logger *zap.Logger) error {
	r := mux.NewRouter()
	httpServer := &http.Server{
		Addr: ":80",
		Handler: handlers.CustomLoggingHandler(os.Stdout, r, func(writer io.Writer, params handlers.LogFormatterParams) {
			dump, _ := httputil.DumpRequest(params.Request, true)
			logger.Info("HTTP request", zap.String("from", GetRequestIP(params.Request)), zap.String("request_dump", string(dump)))
			//writer.Write(dump)
		}),
	}

	return httpServer.ListenAndServe()
}

func main() {
	logger, _ := zap.NewProduction()
	go LogDNS(logger)
	LogHTTP(logger)
}

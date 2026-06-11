package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	//"github.com/pion/transport/v2/stdnet"
	"github.com/pion/turn/v2"
)

var (
	server = flag.String("server",
		"localhost:3478",
		"turn server address",
	)

	username     = flag.String("u", "user", "username")
	password     = flag.String("p", "secret", "password")
	realm        = flag.String("r", "", "realm")
	socksProx    = flag.Bool("socks5", false, "Start a SOCKS5 server")
	httpProx     = flag.Bool("http", false, "Start HTTP Proxy")
	socksPort    = flag.Int("sp", 8000, "Port to use for SOCKS server")
	httpPort     = flag.Int("hp", 8080, "Port to use for HTTP Proxy")
	socksHost    = flag.String("sh", "127.0.0.1", "Host addr to listen on SOCKS5 (default 127.0.0.1)")
	httpHost     = flag.String("hh", "127.0.0.1", "Host addr to listen on HTTP (default 127.0.0.1)")
)

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func bufHeader(src http.Header) []byte {
	buf := make([]byte, 0)
	for k, vv := range src {
		buf = append(buf, []byte(k)...)
		buf = append(buf, []byte(":")...)
		for _, v := range vv {
			buf = append(buf, []byte(v)...)
		}
		buf = append(buf, []byte("\r\n")...)
	}
	return buf
}

// this function is such an ugly hack but I'm tired and it works
// look at replacing with real code that does io.Copy and
// better buffer handling
// this drains http headers, constructs manual method line
// and manual host line
// then sends everything to the server
func handleHTTP(w http.ResponseWriter, r *http.Request) {

	target := r.URL.Host
	if target == "" {
		w.Write([]byte("This is a HTTP Proxy, use it as such"))
		return
	}

	port := r.URL.Port()

	if port == "" {
		port = "80"
	}
	peer := target
	if strings.Index(target, ":") == -1 {
		peer = fmt.Sprintf("%s:%s", target, port)
	}
	log.Printf("[*] Proxy to peer: %s", peer)

	relayedConn, err := connectTurn(peer)
	if err != nil {
		log.Printf("[x] error setting up STUN %s", err)
		http.Error(w, "Proxy encountered error", http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}
	conn, bufwr, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//ugly hack to recreate same function that could be achieved with httputil.DumpRequest
	// create method line
	methodLine := fmt.Sprintf("%s %s %s\r\n", r.Method, r.URL.Path, r.Proto)
	hostLine := fmt.Sprintf("Host: %s\r\n", target)
	relayedConn.Write([]byte(methodLine))
	relayedConn.Write([]byte(hostLine))
	relayedConn.Write(bufHeader(r.Header))
	relayedConn.Write([]byte("\r\n"))
	//drain body

	io.Copy(relayedConn, r.Body)
	io.Copy(bufwr, relayedConn)

	// close the connections
	defer conn.Close()
	defer relayedConn.Close()
}

func handleProxyTun(w http.ResponseWriter, r *http.Request) {

	target := r.URL.Host
	if target == "" {
		w.Write([]byte("This is a HTTP Proxy, use it as such"))
		return
	}

	port := r.URL.Port()

	if port == "" {
		port = "80"
	}
	peer := r.Host

	relayedConn, err := connectTurn(peer)
	if err != nil {
		log.Printf("[x] error setting up STUN %s %v %v", err, peer, port)
		w.WriteHeader(http.StatusInternalServerError)
		//clientConn.Write([]byte("Proxy encountered error"))
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go transfer(relayedConn, clientConn)
	go transfer(clientConn, relayedConn)

}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

var (
	dnsIdx  int
	dnsMu   sync.Mutex
	dnsList = []string{"1.1.1.1:53", "8.8.8.8:53"}
)

var customResolver = &net.Resolver{
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		dnsMu.Lock()
		srv := dnsList[dnsIdx%len(dnsList)]
		dnsIdx++
		dnsMu.Unlock()
		d := net.Dialer{}
		return d.DialContext(ctx, "udp", srv)
	},
}

func resolveTCPWithDNS(addr string, r *net.Resolver) (*net.TCPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", addrs[0])
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func connectTurn(target string) (net.Conn, error) {
	raddr, err := resolveTCPWithDNS(*server, customResolver)
	if err != nil {
		log.Println(err, raddr)
		return nil, err
	}
	conn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	log.Printf("[*] Dial server %s -> %s", conn.LocalAddr(), conn.RemoteAddr())

	if true {
		tcp := conn
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(15 * time.Second)
	}
	stunConn := turn.NewSTUNConn(conn)

/*
	baseNet, err := stdnet.NewNet()
	if err != nil {
		conn.Close()
		log.Println(err)
		return nil, err
	}
*/
	log.Println(*username, *password, *realm)
	serverIP := raddr.String()
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: serverIP,
		TURNServerAddr: serverIP,
		Conn:           stunConn,
		// Net:            baseNet,
		Username:       *username,
		Password:       *password,
		Realm:          *realm,
		// Software:       "turner-proxy",
	})
	if err != nil {
		conn.Close()
		log.Println(err)
		return nil, err
	}
	if err = client.Listen(); err != nil {
		client.Close()
		log.Println(err)
		return nil, err
	}

	// 1) AllocateTCP first (sets realm/nonce/integrity from server challenge)
	log.Println("AllocateTCP...")
	alloc, err := client.AllocateTCP()
	if err != nil {
		client.Close()
		log.Println(err)
		return nil, err
	}
	log.Printf("relay addr = %s", alloc.Addr())

	// 2) Binding after Allocate (turnpool pattern)
	if maddr, err := client.SendBindingRequest(); err != nil {
		log.Printf("SendBindingRequest fail: %v (non-fatal)", err)
	} else {
		log.Printf("mapped addr = %s", maddr)
	}

	// 3) Resolve target
	targetAddr, err := resolveTCPWithDNS(target, customResolver)
	if err != nil {
		alloc.Close()
		client.Close()
		log.Println(err)
		return nil, err
	}
	log.Printf("[*] Relay to %s via TURN", targetAddr.String())

	// 4) CreatePermissions for target (matching turnpool pattern)
	if err := alloc.CreatePermissions(targetAddr); err != nil {
		log.Printf("CreatePermissions fail: %v", err)
	}
	
	//ttaddr := &net.TCPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	ttaddr := &net.TCPAddr{IP: net.IPv4(185, 45, 5, 35), Port: 443}
	cid, err := alloc.Connect(ttaddr)
	log.Println(cid, err)
	
	_, err = alloc.DialTCP("tcp", nil, targetAddr)
	log.Println(err)

	// 5) Dial data connection + Connect + BindConnection
	dataConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		alloc.Close()
		client.Close()
		log.Println(err)
		return nil, err
	}

	log.Printf("DialTCPWithConn to %s...", targetAddr.String())
	relayedConn, err := alloc.DialTCPWithConn(dataConn, "tcp", targetAddr)
	if err != nil {
		dataConn.Close()
		alloc.Close()
		client.Close()
		log.Printf("DialTCPWithConn FAIL: %v, 446 maybe not support RFC 6062 出站 relay", err)
		return nil, err
	}
	log.Printf("DialTCPWithConn OK")

	return relayedConn, nil
}

func turnDial(ctx context.Context, network, addr string) (net.Conn, error) {
	cnn, err := connectTurn(addr)
	if err != nil {
		return nil, err
	}
	return cnn, nil
}

func main() {
	log.SetFlags(log.Lshortfile | log.Ltime)
	flag.Parse()

	if !*httpProx && !*socksProx {
		log.Println("[x] No mode selected. Use either, or both, -http or -socks5")
		return
	}
	errChan := make(chan error)

	if *httpProx {
		go func(errChan chan error) {
			log.Printf("[*] Starting HTTP Server on %s:%d", *httpHost, *httpPort)
			httpServer := &http.Server{
				Addr: fmt.Sprintf("%s:%d", *httpHost, *httpPort),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodConnect {
						handleProxyTun(w, r)
					} else {
						handleHTTP(w, r)
					}
				}),
				// Disable HTTP/2.
				//TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
			}
			errChan <- httpServer.ListenAndServe()
		}(errChan)
	}

	if *socksProx {
		log.Printf("[*] Starting SOCKS5 Server on %s:%d", *socksHost, *socksPort)
		go func(errChan chan error) {
			conf := &socks5.Config{Dial: turnDial}
			server, err := socks5.New(conf)
			if err != nil {
				errChan <- err
				return
			}

			// Create SOCKS5 proxy on localhost port 8000
			errChan <- server.ListenAndServe("tcp", fmt.Sprintf("%s:%d", *socksHost, *socksPort))
		}(errChan)
	}

	select {
	case <-errChan:
		log.Println("Error setting up server.", errChan)
	}
}

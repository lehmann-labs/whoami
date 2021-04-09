package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Units.
const (
	_        = iota
	KB int64 = 1 << (10 * iota)
	MB
	GB
	TB
)

var (
	cert string
	key  string
	port string
	name string
)

func init() {
	loglevel := os.Getenv("LOG_LEVEL")

	flag.StringVar(&cert, "cert", "", "give me a certificate")
	flag.StringVar(&key, "key", "", "give me a key")
	flag.StringVar(&port, "port", "80", "give me a port number")
	flag.StringVar(&name, "name", os.Getenv("WHOAMI_NAME"), "give me a name")

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if strings.ToLower(loglevel)=="debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func main() {
	flag.Parse()

	http.HandleFunc("/data", dataHandler)
	http.HandleFunc("/echo", echoHandler)
	http.HandleFunc("/bench", benchHandler)
	http.HandleFunc("/", whoamiHandler)
	http.HandleFunc("/api", apiHandler)
	http.HandleFunc("/health", healthHandler)

	log.Info().Str("port", port).Msg("Starting up")

	if len(cert) > 0 && len(key) > 0 {
		if err:=http.ListenAndServeTLS(":"+port, cert, key, nil);err!=nil {
			log.Fatal().Err(err).Msg("Could not start server")
		}
	}
	if err:=http.ListenAndServe(":"+port, nil);err!=nil {
		log.Fatal().Err(err).Msg("Could not start server")
	}
}

func benchHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("handler","benchHandler").Str("from",r.RemoteAddr).Msg("Got request")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "text/plain")
	log.Debug().Str("handler","benchHandler").Str("from",r.RemoteAddr).Msg("Responding")
	_, _ = fmt.Fprint(w, "1")
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("handler","echoHandler").Str("from",r.RemoteAddr).Msg("Got request")
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msg("Error in echoHandler")
		return
	}

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			return
		}

		printBinary(p)
		err = conn.WriteMessage(messageType, p)
		if err != nil {
			return
		}
	}
}

func printBinary(s []byte) {
	log.Info().Msg("Received b:")
	for n := 0; n < len(s); n++ {
		log.Info().Msgf("%d,", s[n])
	}
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("handler","dataHandler").Str("from",r.RemoteAddr).Msg("Got request")
	u, _ := url.Parse(r.URL.String())
	queryParams := u.Query()

	size, err := strconv.ParseInt(queryParams.Get("size"), 10, 64)
	if err != nil {
		size = 1
	}
	if size < 0 {
		size = 0
	}

	unit := queryParams.Get("unit")
	switch strings.ToLower(unit) {
	case "kb":
		size *= KB
	case "mb":
		size *= MB
	case "gb":
		size *= GB
	case "tb":
		size *= TB
	}

	attachment, err := strconv.ParseBool(queryParams.Get("attachment"))
	if err != nil {
		attachment = false
	}

	content := fillContent(size)

	if attachment {
		w.Header().Set("Content-Disposition", "Attachment")
		http.ServeContent(w, r, "data.txt", time.Now(), content)
		return
	}

	if _, err := io.Copy(w, content); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("handler","whoamiHandler").Str("from", r.RemoteAddr).Msg("Got request")
	u, _ := url.Parse(r.URL.String())
	wait := u.Query().Get("wait")
	if len(wait) > 0 {
		duration, err := time.ParseDuration(wait)
		if err == nil {
			time.Sleep(duration)
		}
	}

	if name != "" {
		_, _ = fmt.Fprintln(w, "Name:", name)
	}

	hostname, _ := os.Hostname()
	_, _ = fmt.Fprintln(w, "Hostname:", hostname)

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			_, _ = fmt.Fprintln(w, "IP:", ip)
		}
	}

	log.Debug().Str("handler","whoamiHandler").Str("from", r.RemoteAddr).Msg("Responding")
	_, _ = fmt.Fprintln(w, "RemoteAddr:", r.RemoteAddr)
	if err := r.Write(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("handler","whoamiHandler").Str("from", r.RemoteAddr).Msg("Got request")
	hostname, _ := os.Hostname()

	data := struct {
		Hostname string      `json:"hostname,omitempty"`
		IP       []string    `json:"ip,omitempty"`
		Headers  http.Header `json:"headers,omitempty"`
		URL      string      `json:"url,omitempty"`
		Host     string      `json:"host,omitempty"`
		Method   string      `json:"method,omitempty"`
		Name     string      `json:"name,omitempty"`
	}{
		Hostname: hostname,
		IP:       []string{},
		Headers:  r.Header,
		URL:      r.URL.RequestURI(),
		Host:     r.Host,
		Method:   r.Method,
		Name:     name,
	}

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				data.IP = append(data.IP, ip.String())
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	log.Debug().Str("handler","whoamiHandler").Str("from", r.RemoteAddr).Msg("Responding")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

type healthState struct {
	StatusCode int
}

var (
	currentHealthState = healthState{http.StatusOK}
	mutexHealthState   = &sync.RWMutex{}
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("handler","healthHandler").Str("from", r.RemoteAddr).Msg("Got request")

	if r.Method == http.MethodPost {
		var statusCode int

		if err := json.NewDecoder(r.Body).Decode(&statusCode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Info().Int("statusCode",statusCode).Msg("Update health check status code.")

		mutexHealthState.Lock()
		defer mutexHealthState.Unlock()
		currentHealthState.StatusCode = statusCode
	} else {
		mutexHealthState.RLock()
		defer mutexHealthState.RUnlock()
		log.Debug().Str("handler","healthHandler").Str("from", r.RemoteAddr).Msg("Responding")
		w.WriteHeader(currentHealthState.StatusCode)
	}
}

func fillContent(length int64) io.ReadSeeker {
	charset := "-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)

	for i := range b {
		b[i] = charset[i%len(charset)]
	}

	if length > 0 {
		b[0] = '|'
		b[length-1] = '|'
	}

	return bytes.NewReader(b)
}

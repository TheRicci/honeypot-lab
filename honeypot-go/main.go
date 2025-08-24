package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
)

type SuricataAlert struct {
	UID       string
	Signature string
	Category  string
	Severity  int
	SrcIP     string
	DestPort  int
	Timestamp time.Time
	EventID   string
}

type Event struct {
	ID           string
	Timestamp    time.Time
	IP           string
	Port         int
	Payload      string
	Session      []string
	Duration     time.Duration
	SuricataData []*SuricataAlert
}

type Honeypot struct {
	ports        []int
	EventMap     map[string]*Event
	eventMutex   sync.RWMutex
	history      []*Event
	suricataJobs chan *Event
	splunkJobs   chan *Event
}

func NewHoneypot(ports []int) *Honeypot {
	hp := &Honeypot{
		ports:        ports,
		EventMap:     make(map[string]*Event),
		history:      []*Event{},
		suricataJobs: make(chan *Event, 100),
		splunkJobs:   make(chan *Event, 100),
	}
	hp.startWorkerPools()
	return hp
}

func (hp *Honeypot) Start() {
	for _, port := range hp.ports {
		switch port {
		case 21:
			// Plain FTP
			go hp.listenFTP(port)
		case 80:
			// Plain HTTP
			go hp.startHTTP(port)
		default:
			go hp.listenOnPort(port)
		}
	}

	// Wait for interrupt
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	<-sigint
	fmt.Println("Shutting down server...")
}

func (hp *Honeypot) listenOnPort(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Printf("[!] Error listening on port %d: %v\n", port, err)
		return
	}
	fmt.Printf("[*] Listening on port %d\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go hp.handleConnection(conn, port)
	}
}

func (hp *Honeypot) handleConnection(conn net.Conn, port int) { //add start and duration
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, _ := reader.ReadString('\n')

	hp.registerEvent(time.Now(), ip, &data, port, nil)
}

func (hp *Honeypot) listenFTP(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		fmt.Printf("[!] Error listening on FTP port %d: %v\n", port, err)
		return
	}
	fmt.Printf("[*] FTP honeypot listening on port %d\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go hp.handleFTPSession(conn, port)
	}
}

func (hp *Honeypot) handleFTPSession(conn net.Conn, port int) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remoteAddr)

	start := time.Now()
	session := []string{}

	// Send welcome banner
	conn.Write([]byte("220 FTP Service Ready\r\n"))
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		cmd := strings.TrimSpace(line)
		session = append(session, cmd)

		if strings.ToUpper(cmd) == "QUIT" {
			conn.Write([]byte("221 Goodbye.\r\n"))
			break
		} else {
			conn.Write([]byte("500 Unknown command.\r\n"))
		}
	}

	duration := time.Since(start)
	hp.registerEvent(start, ip, nil, port, &ftpData{duration: duration, session: session})
}

type ftpData struct {
	session  []string
	duration time.Duration
}

func (hp *Honeypot) registerEvent(t time.Time, ip string, payload *string, port int, ftp *ftpData) {
	id := makeEventID(ip, port, t)

	event := Event{
		ID:        id,
		Timestamp: t,
		IP:        ip,
		Port:      port,
	}

	if ftp != nil {
		event.Session = ftp.session
		event.Duration = ftp.duration
	} else {
		event.Payload = *payload
	}

	hp.eventMutex.Lock()
	hp.EventMap[id] = &event
	hp.eventMutex.Unlock()

	fmt.Printf("[LOG] %s - %s:%d > %s\n", event.Timestamp.Format(time.RFC3339), event.IP, event.Port, event.Payload)
	if len(event.Session) > 0 {
		fmt.Printf("[SESSION from %s] Duration: %s\n", event.IP, event.Duration)
		for _, cmd := range event.Session {
			fmt.Printf("\t> %s\n", cmd)
		}
	}

	hp.suricataJobs <- &event
}

func main() {
	hp := NewHoneypot([]int{80, 21, 22})
	hp.Start()

	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	<-sigint
	fmt.Println("Shutting down server...")
}

func (hp *Honeypot) startHTTP(port int) {
	mux := http.NewServeMux()

	wrap := func(handler func(http.ResponseWriter, *http.Request) string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			info := handler(w, r)
			ip := strings.Split(r.RemoteAddr, ":")[0]

			hp.registerEvent(time.Now(), ip, &info, port, nil)
		}
	}

	mux.HandleFunc("/search", wrap(sqlInjectionBait))
	mux.HandleFunc("/comment", wrap(xssBait))
	mux.HandleFunc("/admin.php", wrap(fakePHPAdmin))
	mux.HandleFunc("/upload", wrap(fakeUpload))
	mux.HandleFunc("/config", wrap(leakConfig))
	mux.HandleFunc("/robots.txt", wrap(serveRobots))
	mux.HandleFunc("/backup.zip", wrap(fakeDownload))
	mux.HandleFunc("/shell.php", wrap(fakeShell))

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	fmt.Printf("[*] HTTP honeypot running on %s\n", addr)
	http.ListenAndServe(addr, mux)
}

func sqlInjectionBait(w http.ResponseWriter, r *http.Request) string {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, "Results for '%s': No results found.", q)
	return fmt.Sprintf("Search query: %s", q)
}

func xssBait(w http.ResponseWriter, r *http.Request) string {
	msg := r.URL.Query().Get("msg")
	fmt.Fprintf(w, "<p>%s</p>", msg)
	return fmt.Sprintf("XSS comment: %s", msg)
}

func fakePHPAdmin(w http.ResponseWriter, r *http.Request) string {
	if r.Method == "POST" {
		r.ParseForm()
		u := r.FormValue("user")
		p := r.FormValue("pass")
		fmt.Fprintln(w, "Access Denied.")
		return fmt.Sprintf("Admin.php login attempt: %s / %s", u, p)
	}
	fmt.Fprintln(w, `
		<!DOCTYPE html>
		<html>
		<head><title>Admin Login</title></head>
		<body>
			<h2>Admin Panel</h2>
			<form method='POST' action='admin.php'>
				User: <input name='user'/><br/>
				Pass: <input name='pass' type='password'/><br/>
				<input type='submit'/>
			</form>
		</body>
		</html>`)
	return "Admin.php login form served"
}

func fakeUpload(w http.ResponseWriter, r *http.Request) string {
	if r.Method == "POST" {
		r.ParseMultipartForm(10 << 20)
		file, handler, err := r.FormFile("upload")
		if err == nil {
			file.Close()
			fmt.Fprintln(w, "File received.")
			return fmt.Sprintf("File uploaded: %s (%d bytes)", handler.Filename, handler.Size)
		}
		fmt.Fprintln(w, "Upload failed.")
		return "Upload error"
	}
	fmt.Fprintln(w, "<form method='POST' enctype='multipart/form-data'>File: <input type='file' name='upload'/><br/><input type='submit'/></form>")
	return "Upload form served"
}

func leakConfig(w http.ResponseWriter, r *http.Request) string {
	fmt.Fprintln(w, "DB_PASS=supersecret\nAPI_KEY=12345-ABCDE")
	return "Config file accessed"
}

func serveRobots(w http.ResponseWriter, r *http.Request) string {
	fmt.Fprintln(w, "User-agent: *\nDisallow: /backup\nDisallow: /admin")
	return "robots.txt requested"
}

func fakeDownload(w http.ResponseWriter, r *http.Request) string {
	w.Header().Set("Content-Disposition", "attachment; filename=backup.zip")
	w.Write([]byte("FAKE_ZIP_CONTENT"))
	return "Backup.zip requested"
}

func fakeShell(w http.ResponseWriter, r *http.Request) string {
	cmd := r.URL.Query().Get("cmd")
	fmt.Fprintf(w, "Output: %s", strings.Repeat("*", len(cmd)))
	return fmt.Sprintf("Web shell command: %s", cmd)
}

func makeEventID(ip string, port int, t time.Time) string {
	randVal := rand.Intn(1000000) + 1
	seed := fmt.Sprintf("%s|%d|%d|%d", ip, port, t.UnixNano(), randVal)
	h := fnv.New64a()
	h.Write([]byte(seed))
	return fmt.Sprintf("%x", h.Sum64())
}

var hecURL = "https://splunk.example.com:8088/services/collector/event"
var hecToken = "YOUR-HEC-TOKEN"

type hecEvent struct {
	Time       int64       `json:"time"`
	Sourcetype string      `json:"sourcetype"`
	Event      interface{} `json:"event"`
}

func sendToSplunk(evt *Event) error {
	payload := hecEvent{
		Time:       evt.Timestamp.Unix(),
		Sourcetype: "honeypot:event",
		Event:      evt,
	}
	data, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", hecURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Splunk "+hecToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("splunk HEC error: %s", resp.Status)
	}
	return nil
}

func (hp *Honeypot) startWorkerPools() {
	const (
		suricataWorkers = 2
		splunkWorkers   = 3
	)
	/*
		// Suricata workers
		for i := 0; i < suricataWorkers; i++ {
			go func() {
				for evt := range hp.suricataJobs {
					if err := hp.GeneratePCAPAndRunSuricata(evt); err != nil {
						fmt.Println("[!] Suricata job error:", err)
					}
				}
			}()
		}
	*/
	// Splunk HEC workers
	for i := 0; i < splunkWorkers; i++ {
		go func() {
			for evt := range hp.splunkJobs {
				if err := sendToSplunk(evt); err != nil {
					fmt.Println("[!] Splunk job error:", err)
				}
			}
		}()
	}
}


package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/GaryBoone/GoStats/stats"
)

// Message describes a message
type Message struct {
	Topic     string
	QoS       byte
	Payload   interface{}
	Sent      time.Time
	Delivered time.Time
	Error     bool
}

// RunResults describes results of a single client / run
type RunResults struct {
	ID          int     `json:"id"`
	Successes   int64   `json:"successes"`
	Failures    int64   `json:"failures"`
	RunTime     float64 `json:"run_time"`
	MsgTimeMin  float64 `json:"msg_time_min"`
	MsgTimeMax  float64 `json:"msg_time_max"`
	MsgTimeMean float64 `json:"msg_time_mean"`
	MsgTimeStd  float64 `json:"msg_time_std"`
	MsgsPerSec  float64 `json:"msgs_per_sec"`
}

// TotalResults describes results of all clients / runs
type TotalResults struct {
	Ratio           float64 `json:"ratio"`
	Successes       int64   `json:"successes"`
	Failures        int64   `json:"failures"`
	TotalRunTime    float64 `json:"total_run_time"`
	AvgRunTime      float64 `json:"avg_run_time"`
	MsgTimeMin      float64 `json:"msg_time_min"`
	MsgTimeMax      float64 `json:"msg_time_max"`
	MsgTimeMeanAvg  float64 `json:"msg_time_mean_avg"`
	MsgTimeMeanStd  float64 `json:"msg_time_mean_std"`
	TotalMsgsPerSec float64 `json:"total_msgs_per_sec"`
	AvgMsgsPerSec   float64 `json:"avg_msgs_per_sec"`
}

// JSONResults are used to export results as a JSON document
type JSONResults struct {
	Runs   []*RunResults `json:"runs"`
	Totals *TotalResults `json:"totals"`
}

func main() {
	var (
		server          = flag.String("server", "8.213.135.102", "MQTT authorization endpoint as http://host:port")
		imPort          = flag.String("im-port", "1883", "MQTT broker port")
		adminPort       = flag.String("admin-port", "18080", "MQTT broker admin port")
		payload         = flag.String("payload", "123", "MQTT message payload. If empty, then payload is generated based on the size parameter")
		secret          = flag.String("secret", "a50f6f2f-3bdc-422e-b02d-45a2ba43439a", "MQTT message aes encrypt key")
		username        = flag.String("username", "9ygqmws2k", "MQTT client username (empty if auth disabled)")
		password        = flag.String("password", "123123", "MQTT client password (empty if auth disabled)")
		groupId         = flag.String("groupId", "ohgqmws2k", "MQTT client password (empty if auth disabled)")
		identity        = flag.Int("identity", 1, "current server`s identity, 1 is sender or 2 is receiver")
		qos             = flag.Int("qos", 1, "QoS for published messages")
		wait            = flag.Int("wait", 60000, "QoS 1 wait timeout in milliseconds")
		size            = flag.Int("size", 100, "Size of the messages payload (bytes)")
		count           = flag.Int("count", 1, "Number of messages to send per client")
		clients         = flag.Int("clients", 10, "Number of clients to start")
		format          = flag.String("format", "text", "Output format: text|json")
		lite            = flag.Bool("lite", true, "ignore msg while running")
		quiet           = flag.Bool("quiet", true, "Suppress logs while running")
		clientPrefix    = flag.String("client-prefix", "44e362c5-8717-4ea7-8f22-c9b1286832971672797923817", "MQTT client id prefix (suffixed with '-<client-num>'")
		clientCert      = flag.String("client-cert", "", "Path to client certificate in PEM format")
		clientKey       = flag.String("client-key", "", "Path to private clientKey in PEM format")
		brokerCaCert    = flag.String("broker-ca-cert", "", "Path to broker CA certificate in PEM format")
		insecure        = flag.Bool("insecure", false, "Skip TLS certificate verification")
		rampUpTimeInSec = flag.Int("ramp-up-time", 0, "Time in seconds to generate clients by default will not wait between load request")
		messageInterval = flag.Int("message-interval", 10, "Time interval in milliseconds to publish message")
	)

	flag.Parse()
	if *clients < 1 {
		log.Fatalf("Invalid arguments: number of clients should be > 1, given: %v", *clients)
	}

	if *count < 1 {
		log.Fatalf("Invalid arguments: messages count should be > 1, given: %v", *count)
	}

	if *clientCert != "" && *clientKey == "" {
		log.Fatal("Invalid arguments: private clientKey path missing")
	}

	if *clientCert == "" && *clientKey != "" {
		log.Fatalf("Invalid arguments: certificate path missing")
	}

	var tlsConfig *tls.Config
	if *clientCert != "" && *clientKey != "" {
		tlsConfig = generateTLSConfig(*clientCert, *clientKey, *brokerCaCert, *insecure)
	}

	resCh := make(chan *RunResults)
	connected := make(chan string)
	beginPub := make(chan bool)
	sleepTime := float64(*rampUpTimeInSec) / float64(*clients)
	for i := 0; i < *clients; i++ {
		if !*quiet {
			log.Println("Starting client ", i)
		}
		c := &Client{
			ID:              i,
			ClientID:        *clientPrefix,
			ServerURL:       *server,
			IMPort:          *imPort,
			AdminPort:       *adminPort,
			BrokerUser:      *username,
			BrokerPass:      *password,
			GroupId:         *groupId,
			MsgPayload:      *payload,
			Identity:        *identity,
			Secret:          *secret,
			MsgSize:         *size,
			MsgCount:        *count,
			MsgQoS:          byte(*qos),
			Quiet:           *quiet,
			Lite:            *lite,
			WaitTimeout:     time.Duration(*wait) * time.Millisecond,
			TLSConfig:       tlsConfig,
			MessageInterval: *messageInterval,
		}
		go c.Run(resCh, connected, beginPub)
		time.Sleep(time.Duration(sleepTime*1000) * time.Millisecond)
	}

	start := time.Now()
	//connectedClients := 0
	//for connectedClients < *clients {
	//	u := <-connected
	//	log.Printf("Client %v is connected, user: %v", connectedClients, u)
	//	connectedClients++
	//}

	//action := "publishing"
	//if *identity == 2 {
	//	action = "receiving"
	//}
	//log.Printf("All clients(size: %v) are connected, will start %s message in 3 seconds...", *clients, action)
	//time.Sleep(time.Duration(3) * time.Second)
	//for i := 0; i < *clients; i++ {
	//	beginPub <- true
	//}

	// collect the results
	results := make([]*RunResults, *clients)
	for i := 0; i < *clients; i++ {
		results[i] = <-resCh
	}
	totalTime := time.Since(start)
	totals := calculateTotalResults(results, totalTime, *clients)

	// print stats
	printResults(results, totals, *format)
}

func createUserAndAddGroup(count int, groupId, url, port string) {
	for i := 0; i < count; i++ {
		var userId = fmt.Sprintf("U_%v", i)
		if !CheckUserExist(userId, url, port) {
			CreateUser(userId, url, port)
		}
	}

	AddGroupMember(count, "admin", groupId, url, port)
}

func calculateTotalResults(results []*RunResults, totalTime time.Duration, sampleSize int) *TotalResults {
	totals := new(TotalResults)
	totals.TotalRunTime = totalTime.Seconds()

	msgTimeMeans := make([]float64, len(results))
	msgsPerSecs := make([]float64, len(results))
	runTimes := make([]float64, len(results))
	bws := make([]float64, len(results))

	totals.MsgTimeMin = results[0].MsgTimeMin
	for i, res := range results {
		totals.Successes += res.Successes
		totals.Failures += res.Failures
		totals.TotalMsgsPerSec += res.MsgsPerSec

		if res.MsgTimeMin < totals.MsgTimeMin {
			totals.MsgTimeMin = res.MsgTimeMin
		}

		if res.MsgTimeMax > totals.MsgTimeMax {
			totals.MsgTimeMax = res.MsgTimeMax
		}

		msgTimeMeans[i] = res.MsgTimeMean
		msgsPerSecs[i] = res.MsgsPerSec
		runTimes[i] = res.RunTime
		bws[i] = res.MsgsPerSec
	}
	totals.Ratio = float64(totals.Successes) / float64(totals.Successes+totals.Failures)
	totals.AvgMsgsPerSec = stats.StatsMean(msgsPerSecs)
	totals.AvgRunTime = stats.StatsMean(runTimes)
	totals.MsgTimeMeanAvg = stats.StatsMean(msgTimeMeans)
	// calculate std if sample is > 1, otherwise leave as 0 (convention)
	if sampleSize > 1 {
		totals.MsgTimeMeanStd = stats.StatsSampleStandardDeviation(msgTimeMeans)
	}

	return totals
}

func printResults(results []*RunResults, totals *TotalResults, format string) {
	log.Println("All message is published.")
	switch format {
	case "json":
		jr := JSONResults{
			Runs:   results,
			Totals: totals,
		}
		data, err := json.Marshal(jr)
		if err != nil {
			log.Fatalf("Error marshalling results: %v", err)
		}
		var out bytes.Buffer
		_ = json.Indent(&out, data, "", "\t")

		fmt.Println(out.String())
	default:
		//for _, res := range results {
		//	fmt.Printf("======= CLIENT %d =======\n", res.ID)
		//	fmt.Printf("Ratio:               %.3f (%d/%d)\n", float64(res.Successes)/float64(res.Successes+res.Failures), res.Successes, res.Successes+res.Failures)
		//	fmt.Printf("Runtime (s):         %.3f\n", res.RunTime)
		//	fmt.Printf("Msg time min (ms):   %.3f\n", res.MsgTimeMin)
		//	fmt.Printf("Msg time max (ms):   %.3f\n", res.MsgTimeMax)
		//	fmt.Printf("Msg time mean (ms):  %.3f\n", res.MsgTimeMean)
		//	fmt.Printf("Msg time std (ms):   %.3f\n", res.MsgTimeStd)
		//	fmt.Printf("Bandwidth (msg/sec): %.3f\n\n", res.MsgsPerSec)
		//}
		fmt.Printf("========= TOTAL (%d) =========\n", len(results))
		fmt.Printf("Total Ratio:                 %.3f (%d/%d)\n", totals.Ratio, totals.Successes, totals.Successes+totals.Failures)
		fmt.Printf("Total Runtime (sec):         %.3f\n", totals.TotalRunTime)
		fmt.Printf("Average Runtime (sec):       %.3f\n", totals.AvgRunTime)
		fmt.Printf("Msg time min (ms):           %.3f\n", totals.MsgTimeMin)
		fmt.Printf("Msg time max (ms):           %.3f\n", totals.MsgTimeMax)
		fmt.Printf("Msg time mean mean (ms):     %.3f\n", totals.MsgTimeMeanAvg)
		fmt.Printf("Msg time mean std (ms):      %.3f\n", totals.MsgTimeMeanStd)
		fmt.Printf("Average Bandwidth (msg/sec): %.3f\n", totals.AvgMsgsPerSec)
		fmt.Printf("Total Bandwidth (msg/sec):   %.3f\n", totals.TotalMsgsPerSec)
	}
}

func generateTLSConfig(certFile string, keyFile string, caFile string, insecure bool) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Error reading certificate files: %v", err)
	}

	var caCertPool *x509.CertPool = nil
	if caFile != "" {
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			log.Fatalf("Error reading CA certificate file: %v", err)
		}

		caCertPool = x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			log.Fatalf("Error parsing CA certificate %v", certFile)
		}
	}

	cfg := tls.Config{
		ClientAuth:         tls.NoClientCert,
		ClientCAs:          nil,
		InsecureSkipVerify: insecure,
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
	}

	return &cfg
}

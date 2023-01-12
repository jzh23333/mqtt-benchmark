package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/krylovsk/mqtt-benchmark/pb"
	"google.golang.org/protobuf/proto"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/GaryBoone/GoStats/stats"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Client implements an MQTT client running benchmark test
type Client struct {
	ID              int
	ClientID        string
	ServerURL       string
	BrokerURL       string
	BrokerUser      string
	BrokerPass      string
	MsgTopic        string
	MsgPayload      string
	Secret          string
	MsgSize         int
	MsgCount        int
	MsgQoS          byte
	Quiet           bool
	WaitTimeout     time.Duration
	TLSConfig       *tls.Config
	MessageInterval int
}

// Run runs benchmark tests and writes results in the provided channel
func (c *Client) Run(res chan *RunResults) {
	newMsgs := make(chan *Message)
	pubMsgs := make(chan *Message)
	doneLogin := make(chan bool)
	doneGen := make(chan bool)
	donePub := make(chan bool)
	runResults := new(RunResults)

	started := time.Now()
	// begin login
	go c.beginLogin(doneLogin)

	log.Printf("CLIENT %d is logging in...", c.ID)
	<-doneLogin
	log.Printf("CLIENT %d login success", c.ID)

	// start generator
	go c.genMessages(newMsgs, doneGen)
	// start publisher
	go c.pubMessages(newMsgs, pubMsgs, doneGen, donePub)

	runResults.ID = c.ID
	times := []float64{}
	for {
		select {
		case m := <-pubMsgs:
			if m.Error {
				log.Printf("CLIENT %v ERROR publishing message: %v: at %v\n", c.ID, m.Topic, m.Sent.Unix())
				runResults.Failures++
			} else {
				//log.Printf("Message published: %v: sent: %v delivered: %v flight time: %v\n", m.Topic, m.Sent, m.Delivered, m.Delivered.Sub(m.Sent))
				runResults.Successes++
				times = append(times, m.Delivered.Sub(m.Sent).Seconds()*1000) // in milliseconds
			}
		case <-donePub:
			// calculate results
			duration := time.Since(started)
			runResults.MsgTimeMin = stats.StatsMin(times)
			runResults.MsgTimeMax = stats.StatsMax(times)
			runResults.MsgTimeMean = stats.StatsMean(times)
			runResults.RunTime = duration.Seconds()
			runResults.MsgsPerSec = float64(runResults.Successes) / duration.Seconds()
			// calculate std if sample is > 1, otherwise leave as 0 (convention)
			if c.MsgCount > 1 {
				runResults.MsgTimeStd = stats.StatsSampleStandardDeviation(times)
			}

			// report results and exit
			res <- runResults
			return
		}
	}
}

func (c *Client) beginLogin(doneLogin chan bool) {
	log.Printf("CLIENT %d begin login", c.ID)

	clientId, _ := uuid.NewUUID()

	postBody, _ := json.Marshal(map[string]string{
		"mobile":   fmt.Sprintf("%011v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(99999999999)),
		"code":     "66666",
		"platform": "2",
		"clientId": clientId.String(),
	})
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(fmt.Sprintf("%s/login", c.ServerURL), "application/json", requestBody)
	if err != nil {
		log.Fatalf("login failure %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	var result = make(map[string]interface{})
	if err = json.Unmarshal(body, &result); err != nil {
		log.Fatalln(err)
	}

	if result["code"].(float64) != 0 {
		log.Panic("login failure")
	}

	data := result["result"].(map[string]interface{})

	userId := data["userId"].(string)
	token := data["token"].(string)

	c.ClientID = clientId.String()
	c.BrokerUser = userId
	c.Secret = extractSecret(token)

	log.Printf("clientId: %s, userId: %s, secret: %s", c.ClientID, c.BrokerUser, c.Secret)

	doneLogin <- true
}

func extractSecret(token string) string {
	base64Text, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		log.Panic(err)
	}
	cipherText, err := AesDecrypt(base64Text, "")
	if err != nil {
		log.Panic(err)
	}

	content := string(cipherText)
	contents := strings.Split(content, "|")
	return contents[1]
}

func (c *Client) genMessages(ch chan *Message, done chan bool) {
	var payload interface{}
	// set payload if specified
	if c.MsgPayload == "" {
		payload = make([]byte, c.MsgSize)
	}

	for i := 0; i < c.MsgCount; i++ {
		msgBytes := getP2PSendMsg("nygqmws2k", c.BrokerUser, fmt.Sprintf("%s-%d", c.MsgPayload, i))
		cipherText, _ := AesEncrypt(msgBytes, c.Secret)
		payload = cipherText

		ch <- &Message{
			Topic:   c.MsgTopic,
			QoS:     c.MsgQoS,
			Payload: payload,
		}
		time.Sleep(time.Duration(c.MessageInterval) * time.Second)
	}

	done <- true
	// log.Printf("CLIENT %v is done generating messages\n", c.ID)
}

func getP2PSendMsg(target, fromUser, content string) []byte {
	var conversationType int32 = 0
	var conversationLine int32 = 0
	var contentType int32 = 1
	var persistFlag int32 = 3
	msg := &pb.Message{
		Conversation: &pb.Conversation{
			Type:   &conversationType,
			Target: &target,
			Line:   &conversationLine,
		},
		FromUser: &fromUser,
		Content: &pb.MessageContent{
			Type:              &contentType,
			SearchableContent: &content,
			PersistFlag:       &persistFlag,
		},
	}
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		log.Panic(err)
	}
	return msgBytes
}

func (c *Client) pubMessages(in, out chan *Message, doneGen, donePub chan bool) {

	onConnected := func(client mqtt.Client) {
		if !c.Quiet {
			log.Printf("CLIENT %v is connected to the broker %v\n", c.ID, c.BrokerURL)
			log.Printf("clientId: %s, fromUser: %s", c.ClientID, c.BrokerUser)
		}
		ctr := 0
		for {
			select {
			case m := <-in:
				m.Sent = time.Now()
				token := client.Publish(m.Topic, m.QoS, false, m.Payload)
				res := token.WaitTimeout(c.WaitTimeout)
				if !res {
					log.Printf("CLIENT %v Timeout sending message: %v\n", c.ID, token.Error())
					m.Error = true
				} else if token.Error() != nil {
					log.Printf("CLIENT %v Error sending message: %v\n", c.ID, token.Error())
					m.Error = true
				} else {
					m.Delivered = time.Now()
					m.Error = false
				}
				out <- m

				if ctr > 0 && ctr%100 == 0 {
					if !c.Quiet {
						log.Printf("CLIENT %v published %v messages and keeps publishing...\n", c.ID, ctr)
					}
				}
				ctr++
			case <-doneGen:
				donePub <- true
				if !c.Quiet {
					log.Printf("CLIENT %v is done publishing\n", c.ID)
				}
				return
			}
		}
	}

	opts := mqtt.NewClientOptions().
		SetProtocolVersion(4).
		AddBroker(c.BrokerURL).
		//SetClientID(fmt.Sprintf("%s-%v", c.ClientID, c.ID)).
		SetClientID(fmt.Sprintf("%s", c.ClientID)).
		SetCleanSession(true).
		SetAutoReconnect(true).
		SetOnConnectHandler(onConnected).
		SetConnectionLostHandler(func(client mqtt.Client, reason error) {
			log.Printf("CLIENT %v lost connection to the broker: %v. Will reconnect...\n", c.ID, reason.Error())
		})
	if c.BrokerUser != "" && c.BrokerPass != "" {
		opts.SetUsername(c.BrokerUser)
		opts.SetPassword(c.BrokerPass)
	}
	if c.TLSConfig != nil {
		opts.SetTLSConfig(c.TLSConfig)
	}

	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.Wait()

	if token.Error() != nil {
		log.Printf("CLIENT %v had error connecting to the broker: %v\n", c.ID, token.Error())
	}
}

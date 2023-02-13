package main

import (
	"bytes"
	"crypto/md5"
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
	"time"

	"github.com/GaryBoone/GoStats/stats"

	"github.com/krylovsk/mqtt-benchmark/mqtt"
)

// Client implements an MQTT client running benchmark test
type Client struct {
	ID              int
	ClientID        string
	ServerURL       string
	IMPort          string
	AdminPort       string
	BrokerUser      string
	BrokerPass      string
	GroupId         string
	MsgPayload      string
	Secret          string
	Identity        int
	MsgSize         int
	MsgCount        int
	MsgQoS          byte
	Quiet           bool
	Lite            bool
	WaitTimeout     time.Duration
	TLSConfig       *tls.Config
	MessageInterval int
}

// Run runs benchmark tests and writes results in the provided channel
func (c *Client) Run(res chan *RunResults, connected chan string, beginPub chan bool) {
	newMsgs := make(chan *Message)
	pubMsgs := make(chan *Message)
	doneGen := make(chan bool)
	donePub := make(chan bool)
	runResults := new(RunResults)

	// load clientUser
	c.loadClientUser()

	started := time.Now()
	// start generator
	go c.genMessages(newMsgs, beginPub, doneGen)
	// start publisher
	go c.pubMessages(newMsgs, pubMsgs, connected, doneGen, donePub)

	runResults.ID = c.ID
	var times []float64
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
			runTime := duration.Seconds()
			runResults.MsgTimeMin = stats.StatsMin(times)
			runResults.MsgTimeMax = stats.StatsMax(times)
			runResults.MsgTimeMean = stats.StatsMean(times)
			runResults.RunTime = runTime
			runResults.MsgsPerSec = float64(runResults.Successes) / runTime
			// calculate std if sample is > 1, otherwise leave as 0 (convention)
			if c.MsgSize > 1 {
				runResults.MsgTimeStd = stats.StatsSampleStandardDeviation(times)
			}

			// report results and exit
			res <- runResults
			return
		}
	}
}

func (c *Client) genMessages(ch chan *Message, beginPub, done chan bool) {
	var payload interface{}

	//<-beginPub

	if c.Identity == 1 {
		topic := "MS"
		for i := 0; i < c.MsgCount; i++ {
			msgBytes := getP2PSendMsg(1, c.GroupId, c.BrokerUser, fmt.Sprintf("%s-%d", c.MsgPayload, i))

			cipherText, _ := AesEncrypt(msgBytes, c.Secret)
			payload = cipherText

			ch <- &Message{
				Topic:   topic,
				QoS:     c.MsgQoS,
				Payload: payload,
			}
			time.Sleep(time.Duration(c.MessageInterval) * time.Millisecond)
		}
	} else {
		topic := "MP"

		interval := 10
		totalInterval := 0
		for {
			ch <- &Message{
				Topic: topic,
			}
			totalInterval += interval
			time.Sleep(time.Duration(interval) * time.Millisecond)

			if totalInterval >= 1800000 {
				break
			}
		}
	}

	done <- true
	// log.Printf("CLIENT %v is done generating messages\n", c.ID)
}

func (c *Client) pubMessages(in, out chan *Message, connected chan string, doneGen, donePub chan bool) {
	//messageHandler := func(client mqtt.Client, msg mqtt.Message) {
	//	log.Printf("Received message from topic: %s", msg.Topic())
	//	if msg.Topic() == "MP" {
	//		result := &pb.PullMessageResult{}
	//		if err := proto.Unmarshal(msg.Payload(), result); err != nil {
	//			log.Fatalln(err)
	//		}
	//		log.Printf("Received message, user %v pull message: %d,%v", c.BrokerUser, len(result.Message), result)
	//	} else if msg.Topic() == "MS" {
	//		result := &pb.Message{}
	//		if err := proto.Unmarshal(msg.Payload(), result); err != nil {
	//			log.Fatalln(err)
	//		}
	//		log.Printf("Received message, user %v send message: %v", c.BrokerUser, result)
	//	} else if msg.Topic() == "MN" {
	//		result := &pb.NotifyMessage{}
	//		if err := proto.Unmarshal(msg.Payload(), result); err != nil {
	//			log.Fatalln(err)
	//		}
	//		log.Printf("User %v received notify message: %v", c.BrokerUser, result)
	//
	//		current := *result.Head - 1
	//		msgBytes := getPullMsg(&current)
	//		cipherText, _ := AesEncrypt(msgBytes, c.Secret)
	//		token := client.Publish("MP", c.MsgQoS, true, cipherText)
	//		res := token.WaitTimeout(c.WaitTimeout)
	//		log.Printf("Send pull message: %v", res)
	//	}
	//}
	onConnected := func(client mqtt.Client) {
		if !c.Quiet {
			log.Printf("CLIENT %v is connected to the broker %v:%v, clientId: %s, fromUser: %s\n",
				c.ID, c.ServerURL, c.IMPort, c.ClientID, c.BrokerUser)
		}
		//connected <- c.BrokerUser
		ctr := 0
		for {
			select {
			case m := <-in:
				if m.Topic == "MP" {
					continue
				}
				m.Sent = time.Now()
				token := client.Publish(m.Topic, m.QoS, true, m.Payload)
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
		AddBroker(fmt.Sprintf("tcp://%s:%s", c.ServerURL, c.IMPort)).
		SetClientID(c.ClientID).
		SetKeepAlive(time.Duration(30) * time.Second).
		SetCleanSession(true).
		SetAutoReconnect(true).
		//SetDefaultPublishHandler(messageHandler).
		SetOnConnectHandler(onConnected).
		SetConnectionLostHandler(func(client mqtt.Client, reason error) {
			log.Printf("CLIENT %v lost connection to the broker: %v. Will reconnect...\n", c.ID, reason.Error())
		})
	if c.BrokerUser != "" && c.BrokerPass != "" {
		opts.SetUsername(c.BrokerUser)
		opts.SetPassword(getPassword(c.BrokerUser, c.Secret))
	}
	if c.TLSConfig != nil {
		opts.SetTLSConfig(c.TLSConfig)
	}

	//mqtt.DEBUG = log.New(os.Stdout, "", 0)
	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.Wait()

	if token.Error() != nil {
		log.Printf("CLIENT %v had error connecting to the broker: %v\n", c.ID, token.Error())
	}
}

func getPassword(username, secret string) string {
	originText := fmt.Sprintf("%s|%v|%s", "testim20330111", time.Now().Unix()*1000, username)
	pwdByte := []byte(originText)
	desPwd := DESEncrypt(pwdByte, []byte("abcdefgh"))
	base64Byte := make([]byte, base64.StdEncoding.EncodedLen(len(desPwd)))
	base64.StdEncoding.Encode(base64Byte, desPwd)
	aesPwd, _ := AesEncrypt(base64Byte, secret)
	return string(aesPwd)
}

func getP2PSendMsg(conversationType int32, target, fromUser, content string) []byte {
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

func getPullMsg(messageId *int64) []byte {
	var pullType int32 = 0
	msg := &pb.PullMessageRequest{
		Id:   messageId,
		Type: &pullType,
	}
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		log.Panic(err)
	}
	return msgBytes
}

func (c *Client) loadClientUser() {
	var userId string
	if c.Identity == 1 {
		userId = fmt.Sprintf("U_%v", c.ID)
	} else {
		userId = fmt.Sprintf("RU_%v", c.ID)
	}
	if !CheckUserExist(userId, c.ServerURL, c.AdminPort) {
		CreateUser(userId, c.ServerURL, c.AdminPort)
	}

	h := md5.New()
	io.WriteString(h, userId)
	clientId := fmt.Sprintf("%x", h.Sum(nil))
	c.Secret = GetSecret(userId, clientId, c.ServerURL, c.AdminPort)
	c.ClientID = clientId
	c.BrokerUser = userId

	if !c.Quiet {
		log.Printf("CLIENT %d user load success, clientId: %s, userId: %s", c.ID, c.ClientID, c.BrokerUser)
	}
}

func (c *Client) login() {
	if !c.Quiet {
		log.Printf("CLIENT %d start login", c.ID)
	}

	clientId, _ := uuid.NewUUID()
	mobile := fmt.Sprintf("%011v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(99999999999))

	postBody, _ := json.Marshal(map[string]string{
		"mobile":   mobile,
		"code":     "66666",
		"platform": "2",
		"clientId": clientId.String(),
	})
	requestBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(fmt.Sprintf("http://%s:8888/login", c.ServerURL), "application/json", requestBody)
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
	c.Secret = ExtractSecret(token)

	if !c.Quiet {
		log.Printf("CLIENT %d login success, mobile: %s, clientId: %s, userId: %s", c.ID, mobile, c.ClientID, c.BrokerUser)
	}
}

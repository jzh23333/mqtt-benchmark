package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	IMPort          string
	AdminPort       string
	BrokerUser      string
	BrokerPass      string
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
func (c *Client) Run(res chan *RunResults) {
	newMsgs := make(chan *Message)
	pubMsgs := make(chan *Message)
	doneGen := make(chan bool)
	donePub := make(chan bool)
	runResults := new(RunResults)

	// load clientUser
	c.loadClientUser()

	started := time.Now()
	// start generator
	go c.genMessages(newMsgs, doneGen)
	// start publisher
	go c.pubMessages(newMsgs, pubMsgs, doneGen, donePub)

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
			runResults.MsgTimeMin = stats.StatsMin(times)
			runResults.MsgTimeMax = stats.StatsMax(times)
			runResults.MsgTimeMean = stats.StatsMean(times)
			runResults.RunTime = duration.Seconds()
			runResults.MsgsPerSec = float64(runResults.Successes) / duration.Seconds()
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

func (c *Client) genMessages(ch chan *Message, done chan bool) {
	var payload interface{}

	for i := 0; i < c.MsgCount; i++ {
		var msgBytes []byte
		var topic string
		if c.Identity == 1 {
			topic = "MS"
			msgBytes = getP2PSendMsg("nygqmws2k", c.BrokerUser, fmt.Sprintf("%s-%d", c.MsgPayload, i))
		} else {
			topic = "MP"
			msgBytes = getPullMsg(0)
		}

		cipherText, _ := AesEncrypt(msgBytes, c.Secret)
		payload = cipherText

		ch <- &Message{
			Topic:   topic,
			QoS:     c.MsgQoS,
			Payload: payload,
		}
		time.Sleep(time.Duration(c.MessageInterval) * time.Millisecond)
	}

	done <- true
	// log.Printf("CLIENT %v is done generating messages\n", c.ID)
}

func (c *Client) pubMessages(in, out chan *Message, doneGen, donePub chan bool) {
	onConnected := func(client mqtt.Client) {
		if !c.Quiet {
			log.Printf("CLIENT %v is connected to the broker %v:%v, clientId: %s, fromUser: %s\n",
				c.ID, c.ServerURL, c.IMPort, c.ClientID, c.BrokerUser)
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

					if !c.Lite {
						log.Printf("received message")
					}
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

func getPullMsg(messageId int64) []byte {
	var pullType int32 = 0
	msg := &pb.PullMessageRequest{
		Id:   &messageId,
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
	if !c.checkUserExist(userId) {
		c.createUser(userId)
	}

	log.Printf("userId: %s", userId)

	clientId, _ := uuid.NewUUID()
	postBody, _ := json.Marshal(map[string]string{
		"userId":   userId,
		"platform": "1",
		"clientId": clientId.String(),
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/user/get_token", c.ServerURL, c.AdminPort), postBody)
	if result["code"].(float64) != 0 {
		log.Panicf("load failure: %v", result)
	}

	data := result["result"].(map[string]interface{})
	token := data["token"].(string)

	c.Secret = extractSecret(token)
	c.ClientID = clientId.String()
	c.BrokerUser = userId

	if !c.Quiet {
		log.Printf("CLIENT %d user load success, clientId: %s, userId: %s", c.ID, c.ClientID, c.BrokerUser)
	}
}

func (c *Client) checkUserExist(userId string) bool {
	postBody, _ := json.Marshal(map[string]string{
		"userId": userId,
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/user/get_info", c.ServerURL, c.AdminPort), postBody)
	if result["code"].(float64) != 0 {
		return false
	}
	return true
}

func (c *Client) createUser(userId string) string {
	mobile := fmt.Sprintf("%011v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(99999999999))
	postBody, _ := json.Marshal(map[string]string{
		"userId":      userId,
		"type":        "0",
		"name":        mobile,
		"displayName": fmt.Sprintf("TestUser<%s>", userId),
		"mobile":      mobile,
		"password":    "123123",
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/user/create", c.ServerURL, c.AdminPort), postBody)
	if result["code"].(float64) != 0 {
		log.Panicf("create user failure: %v", result)
	}
	data := result["result"].(map[string]interface{})
	return data["userId"].(string)
}

func adminPost(url string, reqBody []byte) map[string]interface{} {
	requestBody := bytes.NewBuffer(reqBody)
	req, err := http.NewRequest(http.MethodPost, url, requestBody)
	if err != nil {
		log.Panicf("new request failure %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	nonce, _ := uuid.NewUUID()
	timestamp := time.Now().UnixNano()
	req.Header.Set("nonce", nonce.String())
	req.Header.Set("timestamp", fmt.Sprintf("%v", timestamp))
	req.Header.Set("sign", getSign(nonce.String(), timestamp))

	client := http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Panicf("request failure %v", err)
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
	return result
}

func getSign(nonce string, timestamp int64) string {
	signStr := fmt.Sprintf("%s|123456|%d", nonce, timestamp)

	hasher := sha1.New()
	hasher.Write([]byte(signStr))
	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha
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
	c.Secret = extractSecret(token)

	if !c.Quiet {
		log.Printf("CLIENT %d login success, mobile: %s, clientId: %s, userId: %s", c.ID, mobile, c.ClientID, c.BrokerUser)
	}
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

package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func CheckUserExist(userId, url, port string) bool {
	postBody, _ := json.Marshal(map[string]string{
		"userId": userId,
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/user/get_info", url, port), postBody)
	if result["code"].(float64) != 0 {
		return false
	}
	return true
}

func CreateUser(userId, url, port string) string {
	mobile := fmt.Sprintf("%011v", rand.New(rand.NewSource(time.Now().UnixNano())).Int63n(99999999999))
	postBody, _ := json.Marshal(map[string]string{
		"userId":      userId,
		"type":        "0",
		"name":        mobile,
		"displayName": fmt.Sprintf("TestUser<%s>", userId),
		"mobile":      mobile,
		"password":    "123123",
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/user/create", url, port), postBody)
	if result["code"].(float64) != 0 {
		log.Panicf("create user failure: %v", result)
	}
	data := result["result"].(map[string]interface{})
	return data["userId"].(string)
}

func CreateGroup(id, count int, userId, url, port string) string {
	members := make([]map[string]string, count)
	for i := 0; i < count; i++ {
		members[i] = map[string]string{
			"member_id": fmt.Sprintf("U_%v", i),
			"alias":     fmt.Sprintf("SU_%v", i),
			"type":      "0",
		}
	}

	postBody, _ := json.Marshal(map[string]interface{}{
		"operator": userId,
		"group": map[string]interface{}{
			"group_info": map[string]string{
				"name":  fmt.Sprintf("Test%v", id),
				"owner": userId,
				"type":  "3",
			},
			"members": members,
		},
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/group/create", url, port), postBody)
	if result["code"].(float64) != 0 {
		log.Panicf("create group failure: %v", result)
	}
	data := result["result"].(map[string]interface{})
	return data["group_id"].(string)
}

func AddGroupMember(count int, userId, groupId, url, port string) {
	members := make([]map[string]string, count)
	for i := 0; i < count; i++ {
		members[i] = map[string]string{
			"member_id": fmt.Sprintf("U_%v", i),
			"name":      fmt.Sprintf("SendUser_%v", i),
			"type":      "0",
		}
	}

	postBody, _ := json.Marshal(map[string]interface{}{
		"operator": userId,
		"group_id": groupId,
		"members":  members,
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/group/member/add", url, port), postBody)
	if result["code"].(float64) != 0 {
		log.Panicf("add group member failure: %v", result)
	}
}

func GetChatroomInfo(chatroomId, url, port string) {
	postBody, _ := json.Marshal(map[string]interface{}{
		"chatroomId": chatroomId,
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/chatroom/info", url, port), postBody)
	if result["code"].(float64) != 0 {
		log.Panicf("add group member failure: %v", result)
	}
	log.Println("chatroomInfo: ", result)
}

func GetSecret(userId, clientId, url, port string) string {
	postBody, _ := json.Marshal(map[string]string{
		"userId":   userId,
		"platform": "1",
		"clientId": clientId,
	})
	result := adminPost(fmt.Sprintf("http://%s:%s/admin/user/get_token", url, port), postBody)
	if result["code"].(float64) != 0 {
		log.Panicf("load failure: %v", result)
	}

	data := result["result"].(map[string]interface{})
	token := data["token"].(string)
	secret := ExtractSecret(token)
	return secret
}

func ExtractSecret(token string) string {
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

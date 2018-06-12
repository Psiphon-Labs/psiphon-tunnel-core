package main

import "C"

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
)

type NoticeEvent struct {
	Data       struct{} `json:"data"`
	NoticeType string   `json:"noticeType"`
}

type PsiphonProvider struct {
}

func (pp PsiphonProvider) Notice(noticeJSON string) {
	var event NoticeEvent
	err := json.Unmarshal([]byte(noticeJSON), &event)
	if err != nil {
		fmt.Printf("Failed to unmarshal: %v", err)
	}
	if event.NoticeType == "Tunnels" {
		fmt.Printf("Connected!!")
	}
	fmt.Println("💣")
	fmt.Printf("%s\n", event.NoticeType)
	fmt.Printf("%s\n", noticeJSON)
}

func (pp PsiphonProvider) HasNetworkConnectivity() int {
	return 1
}

func (pp PsiphonProvider) BindToDevice(fileDescriptor int) (string, error) {
	return "", nil
}

func (pp PsiphonProvider) IPv6Synthesize(IPv4Addr string) string {
	return "::1"
}

func (pp PsiphonProvider) GetPrimaryDnsServer() string {
	return "8.8.8.8"
}

func (pp PsiphonProvider) GetSecondaryDnsServer() string {
	return "8.8.8.8"
}

func (pp PsiphonProvider) GetNetworkID() string {
	return ""
}

const runtimeTimeout = 90 * time.Second

var provider PsiphonProvider

type StartResult struct {
	BootstrapTime float64 `json:"bootstrap_time"`
	ErrorString   string  `json:"error"`
}

//export Start
func Start(configJSON,
	embeddedServerEntryList string) string {

	var result StartResult

	startTime := time.Now().UTC()
	connectedCtx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancel()

	fmt.Printf("Passing: %s\n", configJSON)

	err := psi.Start(configJSON, embeddedServerEntryList, "", provider, true, false)
	if err != nil {
		fmt.Println(err)
	}
	select {
	case <-connectedCtx.Done():
		err := connectedCtx.Err()
		if err != nil {
			result.ErrorString = err.Error()
			Stop()
		}
		delta := time.Now().UTC().Sub(startTime)
		result.BootstrapTime = delta.Seconds()
		b, err := json.Marshal(result)
		if err != nil {
			return "{\"error\":\"json_serializitation\"}"
		}
		return string(b)
	}
}

//export Stop
func Stop() bool {
	psi.Stop()
	return true
}

func main() {
	var configFilename string
	flag.StringVar(&configFilename, "config", "", "configuration input file")
	flag.Parse()

	if configFilename == "" {
		fmt.Println("A config file is required")
		os.Exit(1)
	}

	configFileContents, err := ioutil.ReadFile(configFilename)
	if err != nil {
		fmt.Printf("Invalid config file: %s\n", err.Error())
		os.Exit(1)
	}

	Start(string(configFileContents), "")
}

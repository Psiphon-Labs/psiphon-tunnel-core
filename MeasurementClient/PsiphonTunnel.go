package main

import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
)

type NoticeEvent struct {
	Data       map[string]interface{} `json:"data"`
	NoticeType string                 `json:"noticeType"`
}

type PsiphonProvider struct {
	connected chan bool
	err       chan error
	stopped   chan bool
	networkID string
}

func (pp PsiphonProvider) Notice(noticeJSON string) {
	var event NoticeEvent

	err := json.Unmarshal([]byte(noticeJSON), &event)
	if err != nil {
		select {
		case pp.err <- err:
		default:
		}
		return
	}

	if event.NoticeType == "Tunnels" {
		count := event.Data["count"].(float64)
		if count > 0 {
			select {
			case pp.connected <- true:
			default:
			}
		}
	}
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
	return pp.networkID
}

var provider PsiphonProvider

type StartResult struct {
	BootstrapTime float64 `json:"bootstrap_time"`
	ErrorString   string  `json:"error,omitempty"`
}

//export Start
func Start(configJSON,
	embeddedServerEntryList, networkID string, timeout int64) *C.char {

	var result StartResult

	provider.networkID = networkID
	provider.connected = make(chan bool)
	provider.stopped = make(chan bool)
	provider.err = make(chan error)

	runtimeTimeout := time.Duration(timeout) * time.Second
	startTime := time.Now().UTC()

	connectedCtx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancel()

	err := psi.Start(configJSON, embeddedServerEntryList, "", provider, false, false)
	if err != nil {
		return errorJsonForC(err)
	}

	select {
	case <-connectedCtx.Done():
		result.BootstrapTime = bootstrapTime(startTime)
		err = connectedCtx.Err()
		if err != nil {
			result.ErrorString = err.Error()
		}
	case <-provider.connected:
		result.BootstrapTime = bootstrapTime(startTime)
		cancel()
	case <-provider.stopped:
		result.BootstrapTime = bootstrapTime(startTime)
		result.ErrorString = "stop signalled before client connected"
		cancel()
	case err := <-provider.err:
		result.BootstrapTime = bootstrapTime(startTime)
		result.ErrorString = err.Error()
		cancel()
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return errorJsonForC(err)
	}

	return C.CString(string(resultJSON))
}

func bootstrapTime(startTime time.Time) float64 {
	delta := time.Now().UTC().Sub(startTime)
	return delta.Seconds()
}

func errorJsonForC(err error) *C.char {
	return C.CString(fmt.Sprintf("{\"error\": \"%s\"}", err.Error()))
}

//export Stop
func Stop() bool {
	psi.Stop()
	select {
	case provider.stopped <- true:
	default:
	}

	return true
}

func main() {} // stub required by cgo

package main

import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

type NoticeEvent struct {
	Data       map[string]interface{} `json:"data"`
	NoticeType string                 `json:"noticeType"`
}

type TestResult struct {
	BootstrapTime  float64 `json:"bootstrap_time,omitempty"`
	ErrorString    string  `json:"error,omitempty"`
	HttpProxyPort  int     `json:"http_proxy_port,omitempty"`
	SocksProxyPort int     `json:"socks_proxy_port,omitempty"`
}

type MeasurementTest struct {
	controllerWaitGroup sync.WaitGroup
	controllerCtx       context.Context
	stopController      context.CancelFunc
	httpProxyPort       int
	socksProxyPort      int
}

var measurementTest MeasurementTest

//export Start
func Start(configJSON, embeddedServerEntryList, networkID string, timeout int64) *C.char {

	// Load provided config

	config, err := psiphon.LoadConfig([]byte(configJSON))
	if err != nil {
		return errorJSONForC(err)
	}

	// Set network ID

	if networkID != "" {
		config.NetworkID = networkID
	}

	// All config fields should be set before calling commit

	err = config.Commit()
	if err != nil {
		return errorJSONForC(err)
	}

	// Setup signals

	connected := make(chan bool)

	testError := make(chan error)

	// Set up notice handling

	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {

			var event NoticeEvent

			err := json.Unmarshal(notice, &event)
			if err != nil {
				err = errors.New(fmt.Sprintf("Failed to unmarshal json: %s", err.Error()))
				select {
				case testError <- err:
				default:
				}
			}

			if event.NoticeType == "ListeningHttpProxyPort" {
				port := event.Data["port"].(float64)
				measurementTest.httpProxyPort = int(port)
			} else if event.NoticeType == "ListeningSocksProxyPort" {
				port := event.Data["port"].(float64)
				measurementTest.socksProxyPort = int(port)
			} else if event.NoticeType == "Tunnels" {
				count := event.Data["count"].(float64)
				if count > 0 {
					select {
					case connected <- true:
					default:
					}
				}
			}
		}))

	// Initialize data store

	err = psiphon.InitDataStore(config)
	if err != nil {
		return errorJSONForC(err)
	}

	// Store embedded server entries

	serverEntries, err := protocol.DecodeServerEntryList(
		embeddedServerEntryList,
		common.GetCurrentTimestamp(),
		protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		return errorJSONForC(err)
	}

	err = psiphon.StoreServerEntries(config, serverEntries, false)
	if err != nil {
		return errorJSONForC(err)
	}

	// Run Psiphon

	controller, err := psiphon.NewController(config)
	if err != nil {
		return errorJSONForC(err)
	}

	measurementTest.controllerCtx, measurementTest.stopController = context.WithCancel(context.Background())

	// Set start time

	startTime := time.Now()

	// Setup timeout signal

	runtimeTimeout := time.Duration(timeout) * time.Second

	timeoutSignal, cancelTimeout := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancelTimeout()

	// Run test

	var result TestResult

	measurementTest.controllerWaitGroup.Add(1)
	go func() {
		defer measurementTest.controllerWaitGroup.Done()
		controller.Run(measurementTest.controllerCtx)

		select {
		case testError <- errors.New("controller.Run exited unexpectedly"):
		default:
		}

		// This is a noop if stopController was already called
		measurementTest.stopController()
	}()

	// Wait for a stop signal, then stop Psiphon and exit

	select {
	case <-connected:
		result.BootstrapTime = secondsBeforeNow(startTime)
		result.HttpProxyPort = measurementTest.httpProxyPort
		result.SocksProxyPort = measurementTest.socksProxyPort
	case <-timeoutSignal.Done():
		err = timeoutSignal.Err()
		if err != nil {
			result.ErrorString = fmt.Sprintf("Timeout occured before Psiphon connected: %s", err.Error())
		} else {
			result.ErrorString = "Timeout cancelled before Psiphon connected"
		}
	case err := <-testError:
		result.ErrorString = err.Error()
	}

	// Return result

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return errorJSONForC(err)
	}

	return C.CString(string(resultJSON))
}

//export Stop
func Stop() {
	if measurementTest.stopController != nil {
		measurementTest.stopController()
	}
	measurementTest.controllerWaitGroup.Wait()
}

func secondsBeforeNow(startTime time.Time) float64 {
	delta := time.Now().Sub(startTime)
	return delta.Seconds()
}

func errorJSONForC(err error) *C.char {
	return C.CString(fmt.Sprintf("{\"error\": \"%s\"}", err.Error()))
}

func main() {} // stub required by cgo

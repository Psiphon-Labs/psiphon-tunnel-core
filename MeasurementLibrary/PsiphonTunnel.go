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

type StartResultCode int

const (
	StartResultCodeSuccess StartResultCode = iota
	StartResultCodeTimeout
	StartResultCodeOtherError
)

type NoticeEvent struct {
	Data       map[string]interface{} `json:"data"`
	NoticeType string                 `json:"noticeType"`
}

type StartResult struct {
	Code           StartResultCode `json:"result_code"`
	BootstrapTime  float64         `json:"bootstrap_time,omitempty"`
	ErrorString    string          `json:"error,omitempty"`
	HttpProxyPort  int             `json:"http_proxy_port,omitempty"`
	SocksProxyPort int             `json:"socks_proxy_port,omitempty"`
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
// Start starts the controller and returns once either of the following has occured: an active tunnel has been
// established, the timeout has elapsed before an active tunnel could be established or an error has occured.
//
// Start returns a StartResult object serialized as a JSON string in the form of a null-terminated buffer of C chars.
// Start will return,
// On success:
//   {
//     "result_code": 0,
//     "bootstrap_time": <time_to_establish_tunnel>,
//     "http_proxy_port": <http_proxy_port_num>,
//     "socks_proxy_port": <socks_proxy_port_num>
//   }
//
// On timeout:
//  {
//    "result_code": 1,
//    "error": <error message>
//  }
//
// On other error:
//   {
//     "result_code": 2,
//     "error": <error message>
//   }
//
// networkID should be not be blank and should follow the format specified by
// https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter.
func Start(configJSON, embeddedServerEntryList, networkID string, timeout int64) *C.char {

	// Load provided config

	config, err := psiphon.LoadConfig([]byte(configJSON))
	if err != nil {
		return startErrorJson(err)
	}

	// Set network ID

	if networkID != "" {
		config.NetworkID = networkID
	}

	// All config fields should be set before calling commit

	err = config.Commit()
	if err != nil {
		return startErrorJson(err)
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
		return startErrorJson(err)
	}

	// Store embedded server entries

	serverEntries, err := protocol.DecodeServerEntryList(
		embeddedServerEntryList,
		common.GetCurrentTimestamp(),
		protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		return startErrorJson(err)
	}

	err = psiphon.StoreServerEntries(config, serverEntries, false)
	if err != nil {
		return startErrorJson(err)
	}

	// Run Psiphon

	controller, err := psiphon.NewController(config)
	if err != nil {
		return startErrorJson(err)
	}

	measurementTest.controllerCtx, measurementTest.stopController = context.WithCancel(context.Background())

	// Set start time

	startTime := time.Now()

	// Setup timeout signal

	runtimeTimeout := time.Duration(timeout) * time.Second

	timeoutSignal, cancelTimeout := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancelTimeout()

	// Run test

	var result StartResult

	measurementTest.controllerWaitGroup.Add(1)
	go func() {
		defer measurementTest.controllerWaitGroup.Done()
		controller.Run(measurementTest.controllerCtx)

		select {
		case testError <- errors.New("controller.Run exited unexpectedly"):
		default:
		}
	}()

	// Wait for an active tunnel, timeout or error

	select {
	case <-connected:
		result.Code = StartResultCodeSuccess
		result.BootstrapTime = secondsBeforeNow(startTime)
		result.HttpProxyPort = measurementTest.httpProxyPort
		result.SocksProxyPort = measurementTest.socksProxyPort
	case <-timeoutSignal.Done():
		result.Code = StartResultCodeTimeout
		err = timeoutSignal.Err()
		if err != nil {
			result.ErrorString = fmt.Sprintf("Timeout occured before Psiphon connected: %s", err.Error())
		}
		measurementTest.stopController()
	case err := <-testError:
		result.Code = StartResultCodeOtherError
		result.ErrorString = err.Error()
		measurementTest.stopController()
	}

	// Return result

	return marshalStartResult(result)
}

//export Stop
// Stop stops the controller if it is running and waits for it to clean up and exit.
//
// Stop should always be called after a successful call to Start to ensure the
// controller is not left running.
func Stop() {
	if measurementTest.stopController != nil {
		measurementTest.stopController()
	}
	measurementTest.controllerWaitGroup.Wait()
}

// secondsBeforeNow returns the delta seconds of the current time subtract startTime.
func secondsBeforeNow(startTime time.Time) float64 {
	delta := time.Now().Sub(startTime)
	return delta.Seconds()
}

// marshalStartResult serializes a StartResult object as a JSON string in the form
// of a null-terminated buffer of C chars.
func marshalStartResult(result StartResult) *C.char {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return C.CString(fmt.Sprintf("{\"result_code\":%d, \"error\": \"%s\"}", StartResultCodeOtherError, err.Error()))
	}

	return C.CString(string(resultJSON))
}

// startErrorJson returns a StartResult object serialized as a JSON string in the form
// of a null-terminated buffer of C chars. The object's return result code will be set to
// StartResultCodeOtherError (2) and its error string set to the error string of the provided error.
//
// The JSON will be in the form of:
// {
//   "result_code": 2,
//   "error": <error message>
// }
func startErrorJson(err error) *C.char {
	var result StartResult
	result.Code = StartResultCodeOtherError
	result.ErrorString = err.Error()

	return marshalStartResult(result)
}

// main is a stub required by cgo.
func main() {}

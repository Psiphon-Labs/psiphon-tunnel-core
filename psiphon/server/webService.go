/*
 * Copyright (c) 2016, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package server

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	golanglog "log"
	"net"
	"net/http"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

type webServer struct {
	serveMux *http.ServeMux
	config   *Config
}

func RunWebServer(config *Config, shutdownBroadcast <-chan struct{}) error {

	webServer := &webServer{
		config: config,
	}

	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/handshake", webServer.handshakeHandler)
	serveMux.HandleFunc("/connected", webServer.connectedHandler)
	serveMux.HandleFunc("/status", webServer.statusHandler)

	certificate, err := tls.X509KeyPair(
		[]byte(config.WebServerCertificate),
		[]byte(config.WebServerPrivateKey))
	if err != nil {
		return psiphon.ContextError(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	// TODO: inherits global log config?
	logWriter := NewLogWriter()
	defer logWriter.Close()

	server := &psiphon.HTTPSServer{
		http.Server{
			Handler:      serveMux,
			TLSConfig:    tlsConfig,
			ReadTimeout:  WEB_SERVER_READ_TIMEOUT,
			WriteTimeout: WEB_SERVER_WRITE_TIMEOUT,
			ErrorLog:     golanglog.New(logWriter, "", 0),
		},
	}

	listener, err := net.Listen(
		"tcp", fmt.Sprintf("%s:%d", config.ServerIPAddress, config.WebServerPort))
	if err != nil {
		return psiphon.ContextError(err)
	}

	log.WithContext().Info("starting")

	err = nil
	errors := make(chan error)
	waitGroup := new(sync.WaitGroup)

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		// Note: will be interrupted by listener.Close()
		err := server.ServeTLS(listener)

		// Can't check for the exact error that Close() will cause in Accept(),
		// (see: https://code.google.com/p/go/issues/detail?id=4373). So using an
		// explicit stop signal to stop gracefully.
		select {
		case <-shutdownBroadcast:
		default:
			if err != nil {
				select {
				case errors <- psiphon.ContextError(err):
				default:
				}
			}
		}

		log.WithContext().Info("stopped")
	}()

	select {
	case <-shutdownBroadcast:
	case err = <-errors:
	}

	listener.Close()

	waitGroup.Wait()

	log.WithContext().Info("exiting")

	return err
}

func (webServer *webServer) checkWebServerSecret(r *http.Request) bool {
	return subtle.ConstantTimeCompare(
		[]byte(r.URL.Query().Get("server_secret")),
		[]byte(webServer.config.WebServerSecret)) == 1
}

func (webServer *webServer) handshakeHandler(w http.ResponseWriter, r *http.Request) {

	if !webServer.checkWebServerSecret(r) {
		// TODO: log more details?
		log.WithContext().Warning("checkWebServerSecret failed")
		// TODO: psi_web returns NotFound in this case
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// TODO: validate; proper log
	log.WithContextFields(LogFields{"queryParams": r.URL.Query()}).Info("handshake")

	// TODO: necessary, in case client sends bogus request body?
	_, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: backwards compatibility cases (only sending the new JSON format response line)
	// TODO: share struct definition with psiphon/serverApi.go?
	// TODO: populate more response data

	var handshakeConfig struct {
		Homepages            []string            `json:"homepages"`
		UpgradeClientVersion string              `json:"upgrade_client_version"`
		PageViewRegexes      []map[string]string `json:"page_view_regexes"`
		HttpsRequestRegexes  []map[string]string `json:"https_request_regexes"`
		EncodedServerList    []string            `json:"encoded_server_list"`
		ClientRegion         string              `json:"client_region"`
		ServerTimestamp      string              `json:"server_timestamp"`
	}

	handshakeConfig.ServerTimestamp = psiphon.GetCurrentTimestamp()

	jsonPayload, err := json.Marshal(handshakeConfig)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	responseBody := append([]byte("Config: "), jsonPayload...)

	w.WriteHeader(http.StatusOK)
	w.Write(responseBody)
}

func (webServer *webServer) connectedHandler(w http.ResponseWriter, r *http.Request) {

	if !webServer.checkWebServerSecret(r) {
		// TODO: log more details?
		log.WithContext().Warning("checkWebServerSecret failed")
		// TODO: psi_web does NotFound in this case
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// TODO: validate; proper log
	log.WithContextFields(LogFields{"queryParams": r.URL.Query()}).Info("connected")

	// TODO: necessary, in case client sends bogus request body?
	_, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var connectedResponse struct {
		ConnectedTimestamp string `json:"connected_timestamp"`
	}

	connectedResponse.ConnectedTimestamp =
		psiphon.TruncateTimestampToHour(psiphon.GetCurrentTimestamp())

	responseBody, err := json.Marshal(connectedResponse)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(responseBody)
}

func (webServer *webServer) statusHandler(w http.ResponseWriter, r *http.Request) {

	if !webServer.checkWebServerSecret(r) {
		// TODO: log more details?
		log.WithContext().Warning("checkWebServerSecret failed")
		// TODO: psi_web does NotFound in this case
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// TODO: validate; proper log
	log.WithContextFields(LogFields{"queryParams": r.URL.Query()}).Info("status")

	// TODO: use json.NewDecoder(r.Body)? But will that handle bogus extra data in request body?
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO: parse payload; validate; proper logs
	log.WithContextFields(LogFields{"payload": string(requestBody)}).Info("status payload")

	w.WriteHeader(http.StatusOK)
}

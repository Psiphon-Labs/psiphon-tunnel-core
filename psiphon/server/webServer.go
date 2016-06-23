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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	golanglog "log"
	"net"
	"net/http"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
)

type webServer struct {
	serveMux       *http.ServeMux
	config         *Config
	psinetDatabase *psinet.Database
}

// RunWebServer runs a web server which supports tunneled and untunneled
// Psiphon API requests.
//
// The HTTP request handlers are light wrappers around the base Psiphon
// API request handlers from the SSH API transport. The SSH API transport
// is preferred by new clients; however the web API transport is still
// required for untunneled final status requests. The web API transport
// may be retired once untunneled final status requests are made obsolete
// (e.g., by server-side bytes transferred stats, by client-side local
// storage of stats for retry, or some other future development).
//
// The API is compatible with all tunnel-core clients but not backwards
// compatible with older clients.
//
func RunWebServer(
	config *Config,
	psinetDatabase *psinet.Database,
	shutdownBroadcast <-chan struct{}) error {

	webServer := &webServer{
		config:         config,
		psinetDatabase: psinetDatabase,
	}

	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/handshake", webServer.handshakeHandler)
	serveMux.HandleFunc("/connected", webServer.connectedHandler)
	serveMux.HandleFunc("/status", webServer.statusHandler)
	serveMux.HandleFunc("/client_verification", webServer.clientVerificationHandler)

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
			MaxHeaderBytes: MAX_API_PARAMS_SIZE,
			Handler:        serveMux,
			TLSConfig:      tlsConfig,
			ReadTimeout:    WEB_SERVER_READ_TIMEOUT,
			WriteTimeout:   WEB_SERVER_WRITE_TIMEOUT,
			ErrorLog:       golanglog.New(logWriter, "", 0),
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

// convertHTTPRequestToAPIRequest converts the HTTP request query
// parameters and request body to the JSON object import format
// expected by the API request handlers.
func convertHTTPRequestToAPIRequest(
	w http.ResponseWriter,
	r *http.Request,
	requestBodyName string) (requestJSONObject, error) {

	params := make(requestJSONObject)

	for name, values := range r.URL.Query() {
		for _, value := range values {
			params[name] = value
			// Note: multiple values per name are ignored
			break
		}
	}

	if requestBodyName != "" {
		r.Body = http.MaxBytesReader(w, r.Body, MAX_API_PARAMS_SIZE)
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, psiphon.ContextError(err)
		}
		var bodyParams requestJSONObject
		err = json.Unmarshal(body, &bodyParams)
		if err != nil {
			return nil, psiphon.ContextError(err)
		}
		params[requestBodyName] = bodyParams
	}

	return params, nil
}

func (webServer *webServer) lookupGeoIPData(params requestJSONObject) GeoIPData {

	clientSessionID, err := getStringRequestParam(params, "client_session_id")
	if err != nil {
		// Not all clients send this parameter
		return NewGeoIPData()
	}

	return GetGeoIPSessionCache(clientSessionID)
}

func (webServer *webServer) handshakeHandler(w http.ResponseWriter, r *http.Request) {

	params, err := convertHTTPRequestToAPIRequest(w, r, "")

	var responsePayload []byte
	if err == nil {
		responsePayload, err = handshakeAPIRequestHandler(
			webServer.config,
			webServer.psinetDatabase,
			webServer.lookupGeoIPData(params),
			params)
	}

	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("failed")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// The legacy response format is newline seperated, name prefixed values.
	// Within that legacy format, the modern JSON response (containing all the
	// legacy response values and more) is single value with a "Config:" prefix.
	// This response uses the legacy format but omits all but the JSON value.
	responseBody := append([]byte("Config: "), responsePayload...)

	w.WriteHeader(http.StatusOK)
	w.Write(responseBody)
}

func (webServer *webServer) connectedHandler(w http.ResponseWriter, r *http.Request) {

	params, err := convertHTTPRequestToAPIRequest(w, r, "")

	var responsePayload []byte
	if err == nil {
		responsePayload, err = connectedAPIRequestHandler(
			webServer.config, webServer.lookupGeoIPData(params), params)
	}

	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("failed")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(responsePayload)
}

func (webServer *webServer) statusHandler(w http.ResponseWriter, r *http.Request) {

	params, err := convertHTTPRequestToAPIRequest(w, r, "statusData")

	if err == nil {
		_, err = statusAPIRequestHandler(
			webServer.config, webServer.lookupGeoIPData(params), params)
	}

	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("failed")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (webServer *webServer) clientVerificationHandler(w http.ResponseWriter, r *http.Request) {

	params, err := convertHTTPRequestToAPIRequest(w, r, "verificationData")

	if err == nil {
		_, err = clientVerificationAPIRequestHandler(
			webServer.config, webServer.lookupGeoIPData(params), params)
	}

	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("failed")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

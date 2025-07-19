package server

import (
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MetadataConfig defines which metadata types each message needs
type MetadataConfig struct {
	ClientMetadata      bool
	DeviceMetadata      bool
	SessionMetadata     bool
	ServerEntryMetadata bool
	ConjureMetadata     bool
	InproxyMetadata     bool
	MeekMetadata        bool
	QuicMetadata        bool
	ShadowsocksMetadata bool
	TLSMetadata         bool
}

// messageMetadataMap defines metadata requirements for each message type
var messageMetadataMap = map[string]MetadataConfig{
	"server_tunnel": {
		ClientMetadata:      true,
		DeviceMetadata:      true,
		SessionMetadata:     true,
		ServerEntryMetadata: true,
		ConjureMetadata:     true,
		InproxyMetadata:     true,
		MeekMetadata:        true,
		QuicMetadata:        true,
		ShadowsocksMetadata: true,
		TLSMetadata:         true,
	},
	"unique_user": {
		ClientMetadata:  true,
		DeviceMetadata:  true,
		SessionMetadata: true,
	},
	"domain_bytes": {
		ClientMetadata:  true,
		DeviceMetadata:  true,
		SessionMetadata: true,
	},
	"server_load":          {},
	"server_load_protocol": {},
	"server_load_dns":      {},
	"irregular_tunnel": {
		ClientMetadata: true,
	},
	"failed_tunnel": {
		ClientMetadata:      true,
		DeviceMetadata:      true,
		SessionMetadata:     true,
		ServerEntryMetadata: true,
		ConjureMetadata:     true,
		InproxyMetadata:     true,
		MeekMetadata:        true,
		QuicMetadata:        true,
		ShadowsocksMetadata: true,
		TLSMetadata:         true,
	},
	"remote_server_list": {
		ClientMetadata:  true,
		DeviceMetadata:  true,
		SessionMetadata: true,
		MeekMetadata:    true,
		TLSMetadata:     true,
	},
	"panic": {},
	"tactics": {
		ClientMetadata:      true,
		DeviceMetadata:      true,
		SessionMetadata:     true,
		ServerEntryMetadata: true,
		MeekMetadata:        true,
		TLSMetadata:         true,
	},
	"inproxy_broker": {
		ClientMetadata:      true,
		DeviceMetadata:      true,
		SessionMetadata:     true,
		ServerEntryMetadata: true,
		MeekMetadata:        true,
	},
}

// newWrapper returns a new pointer to a PsiphondMetric protobuf message with the common fields populated.
func newWrapper(ts *timestamppb.Timestamp, hostType string) *pb.PsiphondMetric {
	// Create the wrapper message
	wrapper := &pb.PsiphondMetric{}

	// Set timestamp (current time if not provided)
	if ts == nil {
		ts = timestamppb.Now()
	}

	wrapper.Timestamp = ts

	// Set host information (moved from HostMetadata)
	wrapper.HostId = logHostID
	wrapper.HostBuildRev = logBuildRev
	if logHostProvider != "" {
		wrapper.HostProvider = logHostProvider
	}

	wrapper.HostType = hostType

	return wrapper
}

// LogFieldsToProtobuf converts a LogFields map to a PsiphondMetric wrapper message.
func LogFieldsToProtobuf(logFields LogFields) []*pb.PsiphondMetric {
	eventName, ok := logFields["event_name"].(string)
	if !ok {
		return nil
	}

	wrapped := []*pb.PsiphondMetric{}

	// Set timestamp (current time if not provided).
	var pbTimestamp *timestamppb.Timestamp
	if timestampStr, exists := logFields["timestamp"].(string); exists {
		if t, err := time.Parse(time.RFC3339, timestampStr); err == nil {
			pbTimestamp = timestamppb.New(t)
		}
	}

	// Set host_type from logFields if available.
	hostType, exists := logFields["host_type"].(string)
	if !exists {
		hostType = ""
	}

	wrapper := newWrapper(pbTimestamp, hostType)

	// Create and populate the specific metric message.
	switch eventName {
	case "server_tunnel":
		msg := &pb.ServerTunnel{}
		populateProtobufMessage(logFields, msg, eventName)

		// Capture the tunnel ID once here to avoid looking it up for every sub-message.
		tunnelID := msg.TunnelId

		// Populate and append the initial server tunnel protobuf message.
		wrapper.Metric = &pb.PsiphondMetric_ServerTunnel{ServerTunnel: msg}
		wrapped = append(wrapped, wrapper)

		// If this message includes asn_dest_bytes_* maps, emit
		// one protobuf ServerTunnelASNDestBytes per ASN.
		if asnBytes, hasASNBytes := logFields["asn_dest_bytes"]; hasASNBytes {
			for asn, totalBytes := range asnBytes.(map[string]int64) {
				msg := &pb.ServerTunnelASNDestBytes{
					TunnelId:  tunnelID,
					DestAsn:   asn,
					DestBytes: totalBytes,
				}

				var value int64
				var exists bool

				value, exists = logFields["asn_dest_bytes_up_tcp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesUpTcp = value
				}

				value, exists = logFields["asn_dest_bytes_down_tcp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesDownTcp = value
				}

				value, exists = logFields["asn_dest_bytes_up_udp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesUpUdp = value
				}

				value, exists = logFields["asn_dest_bytes_down_udp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesDownUdp = value
				}

				wrapper = newWrapper(pbTimestamp, hostType)
				wrapper.Metric = &pb.PsiphondMetric_ServerTunnelAsnDestBytes{ServerTunnelAsnDestBytes: msg}
				wrapped = append(wrapped, wrapper)
			}
		}

		// Return early with the slice of wrapped messages here to skip
		// extra append attempts at the end of this switch, since we've
		// manually appended all of the wrapper messages ourselves.
		return wrapped
	case "unique_user":
		msg := &pb.UniqueUser{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_UniqueUser{UniqueUser: msg}
	case "domain_bytes":
		msg := &pb.DomainBytes{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_DomainBytes{DomainBytes: msg}
	case "server_load":
		if region, hasRegion := logFields["region"]; hasRegion {
			for _, proto := range protocol.SupportedTunnelProtocols {
				if _, exists := logFields[proto]; exists {
					protoStats := logFields[proto].(map[string]any)

					msg := &pb.ServerLoadProtocol{
						Protocol: proto,
						Region:   region.(string),
					}

					var value int64
					var exists bool

					value, exists = protoStats["accepted_clients"].(int64)
					if exists {
						msg.AcceptedClients = value
					}

					value, exists = protoStats["established_clients"].(int64)
					if exists {
						msg.EstablishedClients = value
					}

					if wrapper == nil {
						wrapper = newWrapper(pbTimestamp, hostType)
					}

					wrapper.Metric = &pb.PsiphondMetric_ServerLoadProtocol{ServerLoadProtocol: msg}
					wrapped = append(wrapped, wrapper)
					wrapper = nil
				}
			}
		} else {
			msg := &pb.ServerLoad{}
			populateProtobufMessage(logFields, msg, eventName)

			if wrapper == nil {
				wrapper = newWrapper(pbTimestamp, hostType)
			}

			wrapper.Metric = &pb.PsiphondMetric_ServerLoad{ServerLoad: msg}
			wrapped = append(wrapped, wrapper)
			wrapper = nil
		}

		if dnsCount, hasDNSCount := logFields["dns_count"]; hasDNSCount {
			for dns, count := range dnsCount.(map[string]int64) {
				msg := &pb.ServerLoadDNS{
					DnsServer: strings.ReplaceAll(dns, "-", "."),
					DnsCount:  count,
				}

				var value int64
				var exists bool

				value, exists = logFields["dns_failed_count"].(map[string]int64)[dns]
				if exists {
					msg.DnsFailedCount = value
				}

				value, exists = logFields["dns_duration"].(map[string]int64)[dns]
				if exists {
					msg.DnsDuration = value
				}

				value, exists = logFields["dns_failed_duration"].(map[string]int64)[dns]
				if exists {
					msg.DnsFailedDuration = value
				}

				if wrapper == nil {
					wrapper = newWrapper(pbTimestamp, hostType)
				}

				wrapper.Metric = &pb.PsiphondMetric_ServerLoadDns{ServerLoadDns: msg}
				wrapped = append(wrapped, wrapper)
				wrapper = nil
			}
		}

		// Return early with the slice of wrapped messages here to skip
		// extra append attempts at the end of this switch, since we've
		// manually appended all of the wrapper messages ourselves.
		return wrapped
	case "irregular_tunnel":
		msg := &pb.IrregularTunnel{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_IrregularTunnel{IrregularTunnel: msg}
	case "failed_tunnel":
		msg := &pb.FailedTunnel{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_FailedTunnel{FailedTunnel: msg}
	case "remote_server_list":
		msg := &pb.RemoteServerList{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_RemoteServerList{RemoteServerList: msg}
	case "panic":
		msg := &pb.ServerPanic{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_ServerPanic{ServerPanic: msg}
	case "tactics":
		msg := &pb.Tactics{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_Tactics{Tactics: msg}
	case "inproxy_broker":
		msg := &pb.InproxyBroker{}
		populateProtobufMessage(logFields, msg, eventName)
		wrapper.Metric = &pb.PsiphondMetric_InproxyBroker{InproxyBroker: msg}
	}

	// Single append for all non-special cases.
	if wrapper != nil {
		wrapped = append(wrapped, wrapper)
	}

	return wrapped
}

// populateClientMetadata populates MetadataClient from LogFields.
func populateClientMetadata(logFields LogFields) *pb.MetadataClient {
	metadata := &pb.MetadataClient{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateDeviceMetadata populates MetadataDevice from LogFields.
func populateDeviceMetadata(logFields LogFields) *pb.MetadataDevice {
	metadata := &pb.MetadataDevice{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateSessionMetadata populates MetadataSession from LogFields.
func populateSessionMetadata(logFields LogFields) *pb.MetadataSession {
	metadata := &pb.MetadataSession{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateServerEntryMetadata populates MetadataServerEntry from LogFields.
func populateServerEntryMetadata(logFields LogFields) *pb.MetadataServerEntry {
	metadata := &pb.MetadataServerEntry{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateConjureMetadata populates ConjureMetadata from LogFields.
func populateConjureMetadata(logFields LogFields) *pb.MetadataConjure {
	metadata := &pb.MetadataConjure{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateInproxyMetadata populates InproxyMetadata from LogFields.
func populateInproxyMetadata(logFields LogFields) *pb.MetadataInproxy {
	metadata := &pb.MetadataInproxy{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateMeekMetadata populates MetadataMeek from LogFields.
func populateMeekMetadata(logFields LogFields) *pb.MetadataMeek {
	metadata := &pb.MetadataMeek{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateQuicMetadata populates QuicMetadata from LogFields.
func populateQuicMetadata(logFields LogFields) *pb.MetadataQuic {
	metadata := &pb.MetadataQuic{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateShadowsocksMetadata populates ShadowsocksMetadata from LogFields.
func populateShadowsocksMetadata(logFields LogFields) *pb.MetadataShadowsocks {
	metadata := &pb.MetadataShadowsocks{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateTLSMetadata populates TLSMetadata from LogFields.
func populateTLSMetadata(logFields LogFields) *pb.MetadataTLS {
	metadata := &pb.MetadataTLS{}
	populateMessageFromFields(logFields, metadata)
	return metadata
}

// populateProtobufMessage is the single function that handles all protobuf message types.
func populateProtobufMessage(logFields LogFields, msg proto.Message, eventName string) {
	config, exists := messageMetadataMap[eventName]
	if !exists {
		// Fallback to reflection-only population.
		populateMessageFromFields(logFields, msg)
		return
	}

	// Populate metadata fields based on configuration.
	populateMetadataFields(logFields, msg, config)

	// Populate remaining fields using reflection.
	populateMessageFromFields(logFields, msg)
}

// populateMetadataFields uses reflection to set metadata sub-messages based on configuration.
func populateMetadataFields(logFields LogFields, msg proto.Message, config MetadataConfig) {
	msgReflectValue := reflect.ValueOf(msg)
	if msgReflectValue.Kind() != reflect.Pointer || msgReflectValue.IsNil() {
		return
	}
	msgValue := msgReflectValue.Elem()
	msgType := msgValue.Type()

	// Iterate through message fields to find and populate metadata fields.
	for i := 0; i < msgValue.NumField(); i++ {
		field := msgValue.Field(i)
		fieldType := msgType.Field(i)

		if !field.CanSet() {
			continue
		}

		switch fieldType.Name {
		case "MetadataClient":
			if config.ClientMetadata {
				field.Set(reflect.ValueOf(populateClientMetadata(logFields)))
			}
		case "MetadataDevice":
			if config.DeviceMetadata {
				field.Set(reflect.ValueOf(populateDeviceMetadata(logFields)))
			}
		case "MetadataSession":
			if config.SessionMetadata {
				field.Set(reflect.ValueOf(populateSessionMetadata(logFields)))
			}
		case "MetadataServerEntry":
			if config.ServerEntryMetadata {
				field.Set(reflect.ValueOf(populateServerEntryMetadata(logFields)))
			}
		case "MetadataConjure":
			if config.MeekMetadata {
				field.Set(reflect.ValueOf(populateConjureMetadata(logFields)))
			}
		case "MetadataInproxy":
			if config.MeekMetadata {
				field.Set(reflect.ValueOf(populateInproxyMetadata(logFields)))
			}
		case "MetadataMeek":
			if config.MeekMetadata {
				field.Set(reflect.ValueOf(populateMeekMetadata(logFields)))
			}
		case "MetadataQuic":
			if config.MeekMetadata {
				field.Set(reflect.ValueOf(populateQuicMetadata(logFields)))
			}
		case "MetadataShadowsocks":
			if config.MeekMetadata {
				field.Set(reflect.ValueOf(populateShadowsocksMetadata(logFields)))
			}
		case "MetadataTLS":
			if config.MeekMetadata {
				field.Set(reflect.ValueOf(populateTLSMetadata(logFields)))
			}
		}
	}
}

// populateMessageFromFields uses reflection to populate protobuf message fields from LogFields.
func populateMessageFromFields(logFields LogFields, msg proto.Message) {
	msgReflectValue := reflect.ValueOf(msg)
	if msgReflectValue.Kind() != reflect.Pointer || msgReflectValue.IsNil() {
		return
	}
	msgValue := msgReflectValue.Elem()
	msgType := msgValue.Type()

	for i := 0; i < msgValue.NumField(); i++ {
		field := msgValue.Field(i)
		fieldType := msgType.Field(i)

		if !field.CanSet() {
			continue
		}

		protoTag := fieldType.Tag.Get("protobuf")
		if protoTag == "" {
			continue
		}

		fieldName := getProtobufFieldName(protoTag)
		if fieldName == "" {
			continue
		}

		logValue, exists := logFields[fieldName]
		if !exists {
			continue
		}

		// Handle special field names that might be mapped differently.
		setFieldValue(field, fieldType, logValue, logFields)
	}
}

// getProtobufFieldName extracts the field name from protobuf struct tag.
func getProtobufFieldName(protoTag string) string {
	// Parse protobuf tag like: "bytes,1,opt,name=host_metadata,json=hostMetadata,proto3".
	parts := strings.SplitSeq(protoTag, ",")
	for part := range parts {
		if trimmed, found := strings.CutPrefix(part, "name="); found {
			return trimmed
		}
	}

	return ""
}

// setFieldValue sets a protobuf field value from a LogFields value.
func setFieldValue(field reflect.Value, fieldType reflect.StructField, logValue any, logFields LogFields) {
	switch field.Kind() {
	case reflect.String:
		if str, ok := logValue.(string); ok {
			// Handle special cases for string fields.
			switch fieldType.Name {
			case "UpstreamProxyType":
				// Ensure lowercase for upstream_proxy_type.
				field.SetString(strings.ToLower(str))
			default:
				field.SetString(str)
			}
		}

	case reflect.Int64:
		switch v := logValue.(type) {
		case int:
			field.SetInt(int64(v))
		case int64:
			field.SetInt(v)
		case string:
			if i, err := strconv.ParseInt(v, 10, 64); err == nil {
				field.SetInt(i)
			}
		}

	case reflect.Uint64:
		switch v := logValue.(type) {
		case uint64:
			field.SetUint(v)
		case int:
			if v >= 0 {
				field.SetUint(uint64(v))
			}
		case int64:
			if v >= 0 {
				field.SetUint(uint64(v))
			}
		case string:
			if u, err := strconv.ParseUint(v, 10, 64); err == nil {
				field.SetUint(u)
			}
		}

	case reflect.Float64:
		switch v := logValue.(type) {
		case float64:
			field.SetFloat(v)
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				field.SetFloat(f)
			}
		}

	case reflect.Bool:
		switch v := logValue.(type) {
		case bool:
			field.SetBool(v)
		case string:
			field.SetBool(v == "1" || strings.ToLower(v) == "true")
		}

	case reflect.Ptr:
		// Handle pointer types (like *timestamppb.Timestamp).
		if field.Type() == reflect.TypeOf((*timestamppb.Timestamp)(nil)) {
			switch v := logValue.(type) {
			case string:
				if v != "" {
					if t, err := time.Parse(time.RFC3339, v); err == nil {
						field.Set(reflect.ValueOf(timestamppb.New(t)))
					}
				}
			case time.Time:
				if !v.IsZero() {
					field.Set(reflect.ValueOf(timestamppb.New(v)))
				}
			case *time.Time:
				if v != nil && !v.IsZero() {
					field.Set(reflect.ValueOf(timestamppb.New(*v)))
				}
			}
		}

	case reflect.Map:
		// Handle map fields like asn_dest_bytes.
		// Currently, the only actual map field has special handling
		// in order to emit one sub-type message per map member, to
		// make downstream processing more consistent and effective.
		if mapValue, ok := logValue.(map[string]int64); ok {
			newMap := reflect.MakeMap(field.Type())
			for k, v := range mapValue {
				keyVal := reflect.ValueOf(k)
				valVal := reflect.ValueOf(v)
				newMap.SetMapIndex(keyVal, valVal)
			}

			field.Set(newMap)
		}
	}

	// Handle special cases for fields that need custom logic.
	handleSpecialFields(field, fieldType, logValue, logFields)
}

// handleSpecialFields handles special field mapping cases.
func handleSpecialFields(field reflect.Value, fieldType reflect.StructField, logValue any, logFields LogFields) {
	switch fieldType.Name {
	case "MeekDialIpAddress", "MeekDialDomain":
		// Handle meek_dial_address splitting
		if dialAddr, ok := logFields["meek_dial_address"].(string); ok {
			host, _, err := net.SplitHostPort(dialAddr)
			if err != nil {
				return
			}
			if fieldType.Name == "MeekDialIpAddress" && net.ParseIP(host) != nil {
				field.SetString(host)
			} else if fieldType.Name == "MeekDialDomain" && net.ParseIP(host) == nil {
				field.SetString(host)
			}
		}

	case "TunnelError":
		// Handle tunnel_error PII redaction
		if errorStr, ok := logValue.(string); ok {
			target := "upstreamproxy error: proxyURI url.Parse: parse "
			index := strings.Index(errorStr, target)
			if index != -1 {
				errorStr = errorStr[:index+len(target)] + "<redacted>"
			}
			field.SetString(errorStr)
		}
	}
}

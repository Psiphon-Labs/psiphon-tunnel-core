package server

import (
	"fmt"
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
	wrapper.HostId = &logHostID
	wrapper.HostBuildRev = &logBuildRev
	if logHostProvider != "" {
		wrapper.Provider = &logHostProvider
	}

	wrapper.HostType = &hostType

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
		hostType = "psiphond"
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
					DestAsn:   &asn,
					DestBytes: &totalBytes,
				}

				var value int64
				var exists bool

				value, exists = logFields["asn_dest_bytes_up_tcp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesUpTcp = &value
				}

				value, exists = logFields["asn_dest_bytes_down_tcp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesDownTcp = &value
				}

				value, exists = logFields["asn_dest_bytes_up_udp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesUpUdp = &value
				}

				value, exists = logFields["asn_dest_bytes_down_udp"].(map[string]int64)[asn]
				if exists {
					msg.DestBytesDownUdp = &value
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
			for _, proto := range append(protocol.SupportedTunnelProtocols, "ALL") {
				if _, exists := logFields[proto]; exists {
					protoStats := logFields[proto].(map[string]any)

					regionString := region.(string)
					msg := &pb.ServerLoadProtocol{
						Protocol: &proto,
						Region:   &regionString,
					}

					var value int64
					var exists bool

					value, exists = protoStats["accepted_clients"].(int64)
					if exists {
						msg.AcceptedClients = &value
					}

					value, exists = protoStats["established_clients"].(int64)
					if exists {
						msg.EstablishedClients = &value
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
				dns = strings.ReplaceAll(dns, "-", ".")
				msg := &pb.ServerLoadDNS{
					DnsServer: &dns,
					DnsCount:  &count,
				}

				var value int64
				var exists bool

				value, exists = logFields["dns_failed_count"].(map[string]int64)[dns]
				if exists {
					msg.DnsFailedCount = &value
				}

				value, exists = logFields["dns_duration"].(map[string]int64)[dns]
				if exists {
					msg.DnsDuration = &value
				}

				value, exists = logFields["dns_failed_duration"].(map[string]int64)[dns]
				if exists {
					msg.DnsFailedDuration = &value
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
			if config.ConjureMetadata {
				field.Set(reflect.ValueOf(populateConjureMetadata(logFields)))
			}
		case "MetadataInproxy":
			if config.InproxyMetadata {
				field.Set(reflect.ValueOf(populateInproxyMetadata(logFields)))
			}
		case "MetadataMeek":
			if config.MeekMetadata {
				field.Set(reflect.ValueOf(populateMeekMetadata(logFields)))
			}
		case "MetadataQuic":
			if config.QuicMetadata {
				field.Set(reflect.ValueOf(populateQuicMetadata(logFields)))
			}
		case "MetadataShadowsocks":
			if config.ShadowsocksMetadata {
				field.Set(reflect.ValueOf(populateShadowsocksMetadata(logFields)))
			}
		case "MetadataTLS":
			if config.TLSMetadata {
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
		if err := setFieldValue(field, fieldType, logValue); err != nil {
			// TODO: Panic if setting the field value fails instead of just logging an error?
			fmt.Println(err)
		}
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

// ConversionError represents an error during type conversion
type ConversionError struct {
	FieldName string
	FromType  string
	ToType    string
	Value     interface{}
	Err       error
}

func (e *ConversionError) Error() string {
	return fmt.Sprintf("failed to convert field %s from %s to %s (value: %v): %v",
		e.FieldName, e.FromType, e.ToType, e.Value, e.Err)
}

// setFieldValue sets a protobuf field value from a LogFields value.
func setFieldValue(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	if logValue == nil {
		return nil // Don't set anything for nil values
	}

	// Handle pointers by creating a new instance and setting recursively
	if field.Kind() == reflect.Ptr {
		return setPointerField(field, fieldType, logValue)
	}

	return setPrimitiveField(field, fieldType, logValue)
}

// setPointerField handles pointer fields by creating new instances
func setPointerField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	elemType := field.Type().Elem()

	// Special handling for timestamppb.Timestamp
	if elemType == reflect.TypeOf(timestamppb.Timestamp{}) {
		ts, err := convertToTimestamp(logValue, fieldType.Name)
		if err != nil {
			return err
		}

		if ts != nil {
			field.Set(reflect.ValueOf(ts))
		}

		return nil
	}

	// For primitive pointer types, create a new instance and set it
	newVal := reflect.New(elemType)
	err := setPrimitiveField(newVal.Elem(), fieldType, logValue)
	if err != nil {
		return err
	}

	field.Set(newVal)

	return nil
}

// setPrimitiveField handles non-pointer fields
func setPrimitiveField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	switch field.Kind() {
	case reflect.String:
		return setStringField(field, fieldType, logValue)
	case reflect.Int, reflect.Int32, reflect.Int64:
		return setIntField(field, fieldType, logValue)
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		return setUintField(field, fieldType, logValue)
	case reflect.Float64:
		return setFloat64Field(field, fieldType, logValue)
	case reflect.Bool:
		return setBoolField(field, fieldType, logValue)
	case reflect.Map:
		return setMapField(field, fieldType, logValue)
	case reflect.Slice:
		return setSliceField(field, fieldType, logValue)
	default:
		return &ConversionError{
			FieldName: fieldType.Name,
			FromType:  fmt.Sprintf("%T", logValue),
			ToType:    field.Kind().String(),
			Value:     logValue,
			Err:       fmt.Errorf("unsupported field kind"),
		}
	}
}

func setStringField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	str, err := convertToString(logValue)
	if err != nil {
		return &ConversionError{
			FieldName: fieldType.Name,
			FromType:  fmt.Sprintf("%T", logValue),
			ToType:    "string",
			Value:     logValue,
			Err:       err,
		}
	}

	// Handle special cases for string fields
	switch fieldType.Name {
	case "UpstreamProxyType":
		field.SetString(strings.ToLower(str))
	default:
		field.SetString(str)
	}

	return nil
}

func setIntField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	convErr := &ConversionError{
		FieldName: fieldType.Name,
		FromType:  fmt.Sprintf("%T", logValue),
		Value:     logValue,
	}

	switch field.Kind() {
	case reflect.Int, reflect.Int64:
		// Because we extensively run on 64-bit architectures and protobuf
		// doesn't have the architecture switching int type, for consistency,
		// we always use int64 in our protos to represent int in go.
		convErr.ToType = "int64"
	case reflect.Int32:
		convErr.ToType = "int32"
	}

	val, err := convertToInt64(logValue)
	if err != nil {
		convErr.Err = err
		return convErr
	}

	field.SetInt(val)
	return nil
}

func setUintField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	convErr := &ConversionError{
		FieldName: fieldType.Name,
		FromType:  fmt.Sprintf("%T", logValue),
		Value:     logValue,
	}

	switch field.Kind() {
	case reflect.Uint, reflect.Uint64:
		// Because we extensively run on 64-bit architectures and protobuf
		// doesn't have the architecture switching int type, for consistency,
		// we always use uint64 in our protos to represent uint in go.
		convErr.ToType = "uint64"
	case reflect.Uint32:
		convErr.ToType = "uint32"
	}

	val, err := convertToUint64(logValue)
	if err != nil {
		convErr.Err = err
		return convErr
	}

	field.SetUint(val)
	return nil
}

func setFloat64Field(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	val, err := convertToFloat64(logValue)
	if err != nil {
		return &ConversionError{
			FieldName: fieldType.Name,
			FromType:  fmt.Sprintf("%T", logValue),
			ToType:    "float64",
			Value:     logValue,
			Err:       err,
		}
	}

	field.SetFloat(val)
	return nil
}

func setBoolField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	val, err := convertToBool(logValue)
	if err != nil {
		return &ConversionError{
			FieldName: fieldType.Name,
			FromType:  fmt.Sprintf("%T", logValue),
			ToType:    "bool",
			Value:     logValue,
			Err:       err,
		}
	}

	field.SetBool(val)
	return nil
}

func setMapField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	mapValue, ok := logValue.(map[string]int64)
	if !ok {
		return &ConversionError{
			FieldName: fieldType.Name,
			FromType:  fmt.Sprintf("%T", logValue),
			ToType:    "map[string]int64",
			Value:     logValue,
			Err:       fmt.Errorf("expected map[string]int64"),
		}
	}

	newMap := reflect.MakeMap(field.Type())

	for k, v := range mapValue {
		newMap.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(v))
	}

	field.Set(newMap)
	return nil
}

func setSliceField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	switch sliceValue := logValue.(type) {
	case []any:
		newSlice := make([]string, 0, len(sliceValue))
		for i, elem := range sliceValue {
			str, ok := elem.(string)
			if !ok {
				return &ConversionError{
					FieldName: fieldType.Name,
					FromType:  fmt.Sprintf("%T", elem),
					ToType:    "string",
					Value:     elem,
					Err:       fmt.Errorf("slice element at index %d is not a string", i),
				}
			}
			newSlice = append(newSlice, str)
		}
		field.Set(reflect.ValueOf(newSlice))

	case []string:
		field.Set(reflect.ValueOf(sliceValue))

	default:
		return &ConversionError{
			FieldName: fieldType.Name,
			FromType:  fmt.Sprintf("%T", logValue),
			ToType:    "[]string",
			Value:     logValue,
			Err:       fmt.Errorf("expected []any or []string"),
		}
	}

	return nil
}

func convertToString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil

	case fmt.Stringer:
		return v.String(), nil

	default:
		return "", fmt.Errorf("cannot convert %T to string", value)
	}
}

func convertToInt64(value any) (int64, error) {
	switch v := value.(type) {
	case int64:
		return v, nil

	case int:
		return int64(v), nil

	case int32:
		return int64(v), nil

	case string:
		if v == "" {
			return 0, fmt.Errorf("cannot convert empty string to int64")
		}

		return strconv.ParseInt(v, 10, 64)

	case float64:
		// Only allow conversion if it's a whole number
		if v == float64(int64(v)) {
			return int64(v), nil
		}

		return 0, fmt.Errorf("float64 %f is not a whole number", v)

	default:
		return 0, fmt.Errorf("cannot convert %T to int64", value)
	}
}

func convertToUint64(value any) (uint64, error) {
	switch v := value.(type) {
	case uint64:
		return v, nil

	case uint:
		return uint64(v), nil

	case uint32:
		return uint64(v), nil

	case int:
		if v < 0 {
			return 0, fmt.Errorf("cannot convert negative int %d to uint64", v)
		}

		return uint64(v), nil

	case int64:
		if v < 0 {
			return 0, fmt.Errorf("cannot convert negative int64 %d to uint64", v)
		}

		return uint64(v), nil

	case string:
		if v == "" {
			return 0, fmt.Errorf("cannot convert empty string to uint64")
		}

		return strconv.ParseUint(v, 10, 64)

	default:
		return 0, fmt.Errorf("cannot convert %T to uint64", value)
	}
}

func convertToFloat64(value any) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil

	case float32:
		return float64(v), nil

	case int:
		return float64(v), nil

	case int64:
		return float64(v), nil

	case string:
		if v == "" {
			return 0, fmt.Errorf("cannot convert empty string to float64")
		}

		return strconv.ParseFloat(v, 64)

	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

func convertToBool(value any) (bool, error) {
	switch v := value.(type) {
	case bool:
		return v, nil

	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "on":
			return true, nil

		case "false", "0", "no", "off", "":
			return false, nil

		default:
			return false, fmt.Errorf("cannot convert string %q to bool", v)
		}
	case int:
		return v != 0, nil

	case int64:
		return v != 0, nil

	default:
		return false, fmt.Errorf("cannot convert %T to bool", value)
	}
}

func convertToTimestamp(value any, fieldName string) (*timestamppb.Timestamp, error) {
	switch v := value.(type) {
	case string:
		if v == "" || v == "None" {
			return nil, nil
		}

		var err error
		var t time.Time
		for _, format := range []string{
			time.RFC3339Nano,
			"2006-01-02T15:04:05.999999999Z0700", // ISO8601 w/ optional TZ offset and up to nanosecond precision.
		} {
			if t, err = time.Parse(format, v); err == nil {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("cannot parse timestamp string %q", v)
		}

		return timestamppb.New(t), nil

	case time.Time:
		if v.IsZero() {
			return nil, nil
		}

		return timestamppb.New(v), nil

	case *time.Time:
		if v == nil || v.IsZero() {
			return nil, nil
		}

		return timestamppb.New(*v), nil

	default:
		return nil, fmt.Errorf("cannot convert %T to timestamp", value)
	}
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

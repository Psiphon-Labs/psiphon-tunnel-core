package server

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	pb "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb/psiphond"
	pbr "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb/router"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FieldGroupConfig defines which field groups each message needs
type FieldGroupConfig struct {
	BaseParams        bool
	DialParams        bool
	InproxyDialParams bool
}

// messageFieldGroups defines field group requirements for each message type
var messageFieldGroups = map[string]FieldGroupConfig{
	"server_tunnel": {
		BaseParams:        true,
		DialParams:        true,
		InproxyDialParams: true,
	},
	"unique_user": {
		BaseParams: true,
	},
	"domain_bytes": {
		BaseParams: true,
	},
	"server_load":          {},
	"server_load_protocol": {},
	"server_load_dns":      {},
	"irregular_tunnel": {
		BaseParams: true,
	},
	"failed_tunnel": {
		BaseParams:        true,
		DialParams:        true,
		InproxyDialParams: true,
	},
	"remote_server_list": {
		BaseParams: true,
		DialParams: true,
	},
	"panic": {},
	"tactics": {
		BaseParams: true,
		DialParams: true,
	},
	"inproxy_broker": {
		BaseParams: true,
	},
	"dsl_relay_get_server_entries": {
		BaseParams: true,
	},
}

// routedMsg returns a new pointer to a populated Router protobuf message.
// The error paths in this function should never be reached, but in rare
// cases where they do, instead of returning an error, we panic, and allow
// the existing recovery and logging message to capture the error.
func routedMsg(msg proto.Message) *pbr.Router {
	md := msg.ProtoReflect().Descriptor()
	metric := md.Oneofs().ByName("metric")
	if metric == nil {
		panic("cannot find oneof field: metric")
	}

	messageType := string(md.FullName())

	metricType := msg.ProtoReflect().WhichOneof(metric).TextName()
	destination := strings.ToLower(strings.ReplaceAll(
		fmt.Sprintf("%s-%s-%s", logDestinationPrefix, md.Name(), metricType), "_", "-",
	))

	serialized, err := proto.Marshal(msg)
	if err != nil {
		panic(fmt.Errorf("failed to serialize inner protobuf message to bytes: %w", err))
	}

	return &pbr.Router{
		Destination: &destination,
		MessageType: &messageType,
		Key:         []byte(logHostID),
		Value:       serialized,
	}
}

// newPsiphondWrapper returns a new pointer to a Psiphond protobuf message with the common fields populated.
func newPsiphondWrapper(ts *timestamppb.Timestamp, hostType string) *pb.Psiphond {
	wrapper := &pb.Psiphond{}

	// Set timestamp (current time if not provided)
	if ts == nil {
		ts = timestamppb.Now()
	}

	wrapper.Timestamp = ts

	wrapper.HostId = &logHostID
	wrapper.HostBuildRev = &logBuildRev
	if logHostProvider != "" {
		wrapper.Provider = &logHostProvider
	}

	wrapper.HostType = &hostType

	return wrapper
}

// LogFieldsToProtobuf converts a LogFields map to a Psiphond wrapper message.
func LogFieldsToProtobuf(logFields LogFields) []*pbr.Router {
	eventName, ok := logFields["event_name"].(string)
	if !ok {
		return nil
	}

	out := []*pbr.Router{}

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

	psiphondWrapped := newPsiphondWrapper(pbTimestamp, hostType)

	// Create and populate the specific metric message.
	switch eventName {
	case "server_tunnel":
		msg := &pb.ServerTunnel{}
		populateProtobufMessage(logFields, msg, eventName)

		// Capture the tunnel ID once here to avoid looking it up for every sub-message.
		tunnelID := msg.TunnelId

		// Populate and append the initial server tunnel protobuf message.
		psiphondWrapped.Metric = &pb.Psiphond_ServerTunnel{ServerTunnel: msg}

		out = append(out, routedMsg(psiphondWrapped))

		// If this message includes asn_dest_bytes_* maps, emit
		// one protobuf ServerTunnelASNDestBytes per ASN.
		if asnBytes, hasASNBytes := logFields["asn_dest_bytes"]; hasASNBytes {
			for asn, totalBytes := range asnBytes.(map[string]int64) {
				msg := &pb.ServerTunnelASNDestBytes{
					TunnelId:  tunnelID,
					DestAsn:   &asn,
					DestBytes: &totalBytes,
				}

				if value, exists := logFields["asn_dest_bytes_up_tcp"].(map[string]int64)[asn]; exists {
					msg.DestBytesUpTcp = &value
				}

				if value, exists := logFields["asn_dest_bytes_down_tcp"].(map[string]int64)[asn]; exists {
					msg.DestBytesDownTcp = &value
				}

				if value, exists := logFields["asn_dest_bytes_up_udp"].(map[string]int64)[asn]; exists {
					msg.DestBytesUpUdp = &value
				}

				if value, exists := logFields["asn_dest_bytes_down_udp"].(map[string]int64)[asn]; exists {
					msg.DestBytesDownUdp = &value
				}

				psiphondWrapped = newPsiphondWrapper(pbTimestamp, hostType)
				psiphondWrapped.Metric = &pb.Psiphond_ServerTunnelAsnDestBytes{ServerTunnelAsnDestBytes: msg}

				out = append(out, routedMsg(psiphondWrapped))
			}
		}

		// Return early with the slice of wrapped messages here to skip
		// extra append attempts at the end of this switch, since we've
		// manually appended all of the wrapper messages ourselves.
		return out
	case "unique_user":
		msg := &pb.UniqueUser{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_UniqueUser{UniqueUser: msg}
	case "domain_bytes":
		msg := &pb.DomainBytes{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_DomainBytes{DomainBytes: msg}
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

					if value, exists := protoStats["accepted_clients"].(int64); exists {
						msg.AcceptedClients = &value
					}

					if value, exists := protoStats["established_clients"].(int64); exists {
						msg.EstablishedClients = &value
					}

					if psiphondWrapped == nil {
						psiphondWrapped = newPsiphondWrapper(pbTimestamp, hostType)
					}

					psiphondWrapped.Metric = &pb.Psiphond_ServerLoadProtocol{ServerLoadProtocol: msg}

					out = append(out, routedMsg(psiphondWrapped))
					psiphondWrapped = nil
				}
			}
		} else {
			msg := &pb.ServerLoad{}
			populateProtobufMessage(logFields, msg, eventName)

			if psiphondWrapped == nil {
				psiphondWrapped = newPsiphondWrapper(pbTimestamp, hostType)
			}

			psiphondWrapped.Metric = &pb.Psiphond_ServerLoad{ServerLoad: msg}
			out = append(out, routedMsg(psiphondWrapped))
			psiphondWrapped = nil
		}

		if dnsCount, hasDNSCount := logFields["dns_count"]; hasDNSCount {
			for dns, count := range dnsCount.(map[string]int64) {
				dns = strings.ReplaceAll(dns, "-", ".")
				msg := &pb.ServerLoadDNS{
					DnsServer: &dns,
					DnsCount:  &count,
				}

				if value, exists := logFields["dns_failed_count"].(map[string]int64)[dns]; exists {
					msg.DnsFailedCount = &value
				}

				if value, exists := logFields["dns_duration"].(map[string]int64)[dns]; exists {
					msg.DnsDuration = &value
				}

				if value, exists := logFields["dns_failed_duration"].(map[string]int64)[dns]; exists {
					msg.DnsFailedDuration = &value
				}

				if psiphondWrapped == nil {
					psiphondWrapped = newPsiphondWrapper(pbTimestamp, hostType)
				}

				psiphondWrapped.Metric = &pb.Psiphond_ServerLoadDns{ServerLoadDns: msg}
				out = append(out, routedMsg(psiphondWrapped))
				psiphondWrapped = nil
			}
		}

		// Return early with the slice of wrapped messages here to skip
		// extra append attempts at the end of this switch, since we've
		// manually appended all of the wrapper messages ourselves.
		return out
	case "irregular_tunnel":
		msg := &pb.IrregularTunnel{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_IrregularTunnel{IrregularTunnel: msg}
	case "failed_tunnel":
		msg := &pb.FailedTunnel{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_FailedTunnel{FailedTunnel: msg}
	case "remote_server_list":
		msg := &pb.RemoteServerList{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_RemoteServerList{RemoteServerList: msg}
	case "panic":
		msg := &pb.ServerPanic{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_ServerPanic{ServerPanic: msg}
	case "tactics":
		msg := &pb.Tactics{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_Tactics{Tactics: msg}
	case "inproxy_broker":
		msg := &pb.InproxyBroker{}
		populateProtobufMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_InproxyBroker{InproxyBroker: msg}
	}

	// Single append for all non-special cases.
	if psiphondWrapped != nil {
		out = append(out, routedMsg(psiphondWrapped))
	}

	return out
}

// populateBaseParams populates BaseParams from LogFields.
func populateBaseParams(logFields LogFields) *pb.BaseParams {
	msg := &pb.BaseParams{}
	populateMessageFromFields(logFields, msg)

	return msg
}

// populateDialParams populates DialParams from LogFields.
func populateDialParams(logFields LogFields) *pb.DialParams {
	msg := &pb.DialParams{}
	populateMessageFromFields(logFields, msg)

	return msg
}

// populateInproxyDialParams populates InproxyDialParams from LogFields.
func populateInproxyDialParams(logFields LogFields) *pb.InproxyDialParams {
	msg := &pb.InproxyDialParams{}
	populateMessageFromFields(logFields, msg)

	return msg
}

// populateProtobufMessage is the single function that handles all protobuf message types.
func populateProtobufMessage(logFields LogFields, msg proto.Message, eventName string) {
	config, exists := messageFieldGroups[eventName]
	if !exists {
		// Fallback to reflection-only population.
		populateMessageFromFields(logFields, msg)
		return
	}

	// Populate field groups based on configuration.
	populateFieldGroups(logFields, msg, config)

	// Populate remaining fields using reflection.
	populateMessageFromFields(logFields, msg)
}

// populateFieldGroups uses reflection to set field group sub-messages based on configuration.
func populateFieldGroups(logFields LogFields, msg proto.Message, config FieldGroupConfig) {
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
		case "BaseParams":
			if config.BaseParams {
				field.Set(reflect.ValueOf(populateBaseParams(logFields)))
			}
		case "DialParams":
			if config.DialParams {
				field.Set(reflect.ValueOf(populateDialParams(logFields)))
			}
		case "InproxyDialParams":
			if config.InproxyDialParams {
				field.Set(reflect.ValueOf(populateInproxyDialParams(logFields)))
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
			panic(fmt.Errorf("failed to set field value: %w", err))
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
	Value     any
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
		ts, err := convertToTimestamp(logValue)
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

	case inproxy.PortMappingTypes:
		newSlice := make([]string, 0, len(sliceValue))
		for _, elem := range sliceValue {
			newSlice = append(newSlice, inproxy.PortMappingType(elem).String())
		}

		field.Set(reflect.ValueOf(newSlice))

	case inproxy.ICECandidateTypes:
		newSlice := make([]string, 0, len(sliceValue))
		for _, elem := range sliceValue {
			newSlice = append(newSlice, inproxy.PortMappingType(elem).String())
		}

		field.Set(reflect.ValueOf(newSlice))

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

	case time.Duration:
		return int64(v), nil

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

func convertToTimestamp(value any) (*timestamppb.Timestamp, error) {
	switch v := value.(type) {
	case string:
		if v == "" || v == "None" {
			return nil, nil
		}

		var err error
		var t time.Time
		for _, format := range []string{
			time.RFC3339Nano,
			"2006-01-02T15:04:05.999999999Z0700", // ISO8601 w/ optional TZ offset; up to nanosecond precision.
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

package server

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	pb "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb/psiphond"
	pbr "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/pb/router"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// protobufFieldGroupConfig defines which field groups each message needs
type protobufFieldGroupConfig struct {
	baseParams        bool
	dialParams        bool
	inproxyDialParams bool
}

// protobufMessageFieldGroups defines field group requirements for each message type
var protobufMessageFieldGroups = map[string]protobufFieldGroupConfig{
	"server_tunnel": {
		baseParams:        true,
		dialParams:        true,
		inproxyDialParams: true,
	},
	"unique_user": {
		baseParams: true,
	},
	"domain_bytes": {
		baseParams: true,
	},
	"server_blocklist_hit": {
		baseParams: true,
	},
	"server_load":          {},
	"server_load_protocol": {},
	"server_load_dns":      {},
	"irregular_tunnel": {
		baseParams: true,
	},
	"failed_tunnel": {
		baseParams:        true,
		dialParams:        true,
		inproxyDialParams: true,
	},
	"remote_server_list": {
		baseParams: true,
		dialParams: true,
	},
	"tactics": {
		baseParams: true,
		dialParams: true,
	},
	"inproxy_broker": {
		baseParams: true,
	},
	"dsl_relay_get_server_entries": {
		baseParams: true,
	},
}

// NewProtobufRoutedMessage returns a populated Router protobuf message.
func NewProtobufRoutedMessage(
	destinationPrefix string, msg proto.Message) (*pbr.Router, error) {

	md := msg.ProtoReflect().Descriptor()
	metric := md.Oneofs().ByName("metric")
	if metric == nil {
		return nil, errors.TraceNew("cannot find oneof field: metric")
	}

	messageType := string(md.FullName())

	metricType := msg.ProtoReflect().WhichOneof(metric).TextName()

	destination := strings.ToLower(strings.ReplaceAll(
		fmt.Sprintf("%s-%s-%s", destinationPrefix, md.Name(), metricType), "_", "-"))

	serialized, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &pbr.Router{
		Destination: &destination,
		MessageType: &messageType,
		Key:         []byte(logHostID),
		Value:       serialized,
	}, nil
}

// newProtobufRoutedMessage returns a new pointer to a populated Router
// protobuf message. The error paths in this function should never be
// reached, but in rare cases where they do, instead of returning an error,
// we panic, and allow the existing recovery and logging message to capture
// the error.
func newProtobufRoutedMessage(msg proto.Message) *pbr.Router {

	routedMsg, err := NewProtobufRoutedMessage(logDestinationPrefix, msg)
	if err != nil {
		panic(err.Error())
	}

	return routedMsg
}

// newPsiphondProtobufMessageWrapper returns a new pointer to a Psiphond
// protobuf message with the common fields populated.
func newPsiphondProtobufMessageWrapper(ts *timestamppb.Timestamp, hostType string) *pb.Psiphond {
	wrapper := &pb.Psiphond{}

	// Set timestamp (current time if not provided)
	if ts == nil {
		ts = timestamppb.Now()
	}

	wrapper.Timestamp = ts
	wrapper.HostId = logHostID
	wrapper.HostBuildRev = logBuildRev
	wrapper.Provider = logHostProvider
	wrapper.HostType = hostType

	return wrapper
}

// logFieldsToProtobuf converts a LogFields map to a Psiphond wrapper message.
func logFieldsToProtobuf(logFields LogFields) []*pbr.Router {
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

	psiphondWrapped := newPsiphondProtobufMessageWrapper(pbTimestamp, hostType)

	// Create and populate the specific metric message.
	switch eventName {
	case "server_tunnel":
		msg := &pb.ServerTunnel{}
		protobufPopulateMessage(logFields, msg, eventName)

		// Capture the tunnel ID once here to avoid looking it up for every sub-message.
		tunnelID := msg.TunnelId

		// Populate and append the initial server tunnel protobuf message.
		psiphondWrapped.Metric = &pb.Psiphond_ServerTunnel{ServerTunnel: msg}

		out = append(out, newProtobufRoutedMessage(psiphondWrapped))

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

				psiphondWrapped = newPsiphondProtobufMessageWrapper(pbTimestamp, hostType)
				psiphondWrapped.Metric = &pb.Psiphond_ServerTunnelAsnDestBytes{ServerTunnelAsnDestBytes: msg}

				out = append(out, newProtobufRoutedMessage(psiphondWrapped))
			}
		}

		// Return early with the slice of wrapped messages here to skip
		// extra append attempts at the end of this switch, since we've
		// manually appended all of the wrapper messages ourselves.
		return out
	case "unique_user":
		msg := &pb.UniqueUser{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_UniqueUser{UniqueUser: msg}
	case "domain_bytes":
		msg := &pb.DomainBytes{}
		protobufPopulateMessage(logFields, msg, eventName)
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

					if value, exists := protoStats["server_entry_tag"].(string); exists {
						msg.ServerEntryTag = &value
					}

					if value, exists := protoStats["accepted_clients"].(int64); exists {
						msg.AcceptedClients = &value
					}

					if value, exists := protoStats["established_clients"].(int64); exists {
						msg.EstablishedClients = &value
					}

					if psiphondWrapped == nil {
						psiphondWrapped = newPsiphondProtobufMessageWrapper(pbTimestamp, hostType)
					}

					psiphondWrapped.Metric = &pb.Psiphond_ServerLoadProtocol{ServerLoadProtocol: msg}

					out = append(out, newProtobufRoutedMessage(psiphondWrapped))
					psiphondWrapped = nil
				}
			}
		} else {
			msg := &pb.ServerLoad{}
			protobufPopulateMessage(logFields, msg, eventName)

			if psiphondWrapped == nil {
				psiphondWrapped = newPsiphondProtobufMessageWrapper(pbTimestamp, hostType)
			}

			psiphondWrapped.Metric = &pb.Psiphond_ServerLoad{ServerLoad: msg}
			out = append(out, newProtobufRoutedMessage(psiphondWrapped))
			psiphondWrapped = nil
		}

		if dnsCount, hasDNSCount := logFields["dns_count"]; hasDNSCount {
			for dns, count := range dnsCount.(map[string]int64) {
				dns = strings.ReplaceAll(dns, "-", ".")
				msg := &pb.ServerLoadDNS{
					DnsServer: &dns,
					DnsCount:  &count,
				}

				if value, exists := logFields["server_entry_tag"].(string); exists {
					msg.ServerEntryTag = &value
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
					psiphondWrapped = newPsiphondProtobufMessageWrapper(pbTimestamp, hostType)
				}

				psiphondWrapped.Metric = &pb.Psiphond_ServerLoadDns{ServerLoadDns: msg}
				out = append(out, newProtobufRoutedMessage(psiphondWrapped))
				psiphondWrapped = nil
			}
		}

		// Return early with the slice of wrapped messages here to skip
		// extra append attempts at the end of this switch, since we've
		// manually appended all of the wrapper messages ourselves.
		return out
	case "irregular_tunnel":
		msg := &pb.IrregularTunnel{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_IrregularTunnel{IrregularTunnel: msg}
	case "failed_tunnel":
		msg := &pb.FailedTunnel{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_FailedTunnel{FailedTunnel: msg}
	case "remote_server_list":
		msg := &pb.RemoteServerList{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_RemoteServerList{RemoteServerList: msg}
	case "panic":
		msg := &pb.ServerPanic{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_ServerPanic{ServerPanic: msg}
	case "tactics":
		msg := &pb.Tactics{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_Tactics{Tactics: msg}
	case "inproxy_broker":
		msg := &pb.InproxyBroker{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_InproxyBroker{InproxyBroker: msg}
	case "server_blocklist_hit":
		msg := &pb.ServerBlocklistHit{}
		protobufPopulateMessage(logFields, msg, eventName)
		psiphondWrapped.Metric = &pb.Psiphond_ServerBlocklist{ServerBlocklist: msg}
	}

	// Single append for all non-special cases.
	if psiphondWrapped != nil {
		out = append(out, newProtobufRoutedMessage(psiphondWrapped))
	}

	return out
}

// protobufPopulateBaseParams populates BaseParams from LogFields.
func protobufPopulateBaseParams(logFields LogFields) *pb.BaseParams {
	msg := &pb.BaseParams{}
	protobufPopulateMessageFromFields(logFields, msg)

	return msg
}

// protobufPopulateDialParams populates DialParams from LogFields.
func protobufPopulateDialParams(logFields LogFields) *pb.DialParams {
	msg := &pb.DialParams{}
	protobufPopulateMessageFromFields(logFields, msg)

	return msg
}

// protobufPopulateInproxyDialParams populates InproxyDialParams from LogFields.
func protobufPopulateInproxyDialParams(logFields LogFields) *pb.InproxyDialParams {
	msg := &pb.InproxyDialParams{}
	protobufPopulateMessageFromFields(logFields, msg)

	return msg
}

// protobufPopulateMessage is the single function that handles all protobuf message types.
func protobufPopulateMessage(logFields LogFields, msg proto.Message, eventName string) {
	config, exists := protobufMessageFieldGroups[eventName]
	if !exists {
		// Fallback to reflection-only population.
		protobufPopulateMessageFromFields(logFields, msg)
		return
	}

	// Populate field groups based on configuration.
	protobufPopulateFieldGroups(logFields, msg, config)

	// Populate remaining fields using reflection.
	protobufPopulateMessageFromFields(logFields, msg)
}

// protobufPopulateFieldGroups uses reflection to set field group sub-messages based on configuration.
func protobufPopulateFieldGroups(logFields LogFields, msg proto.Message, config protobufFieldGroupConfig) {
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
			if config.baseParams {
				field.Set(reflect.ValueOf(protobufPopulateBaseParams(logFields)))
			}
		case "DialParams":
			if config.dialParams {
				field.Set(reflect.ValueOf(protobufPopulateDialParams(logFields)))
			}
		case "InproxyDialParams":
			if config.inproxyDialParams {
				field.Set(reflect.ValueOf(protobufPopulateInproxyDialParams(logFields)))
			}
		}
	}
}

// protobufPopulateMessageFromFields uses reflection to populate protobuf message fields from LogFields.
func protobufPopulateMessageFromFields(logFields LogFields, msg proto.Message) {
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
		if err := setProtobufFieldValue(field, fieldType, logValue); err != nil {
			panic(errors.Tracef("failed to set field value: %w", err))
		}
	}
}

// getProtobufFieldName extracts the field name from protobuf struct tag.
//
// Example:
// - in: "bytes,1,opt,name=host_metadata,json=hostMetadata,proto3"
// - out: "host_metadata"
func getProtobufFieldName(protoTag string) string {

	n := len(protoTag)

	// Process the input byte-by-byte to avoid allocations.

	for i := 0; i < n; {

		// Find the end of this comma-delimited part of the tag.
		j := i
		for j < n && protoTag[j] != ',' {
			j++
		}

		// Check for "name=" at the start of this part.
		if j-i >= 5 &&
			protoTag[i] == 'n' &&
			protoTag[i+1] == 'a' &&
			protoTag[i+2] == 'm' &&
			protoTag[i+3] == 'e' &&
			protoTag[i+4] == '=' {

			// Return the slice after "name=".
			return protoTag[i+5 : j]
		}

		// Skip to the start of next part of the tag.
		i = j + 1
	}

	return ""
}

// setProtobufFieldValue sets a protobuf field value from a LogFields value.
func setProtobufFieldValue(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	if logValue == nil {
		return nil // Don't set anything for nil values
	}

	var err error

	// Handle pointers by creating a new instance and setting recursively
	if field.Kind() == reflect.Ptr {
		err = setProtobufPointerField(field, fieldType, logValue)
	} else {
		err = setProtobufPrimitiveField(field, fieldType, logValue)
	}

	if err != nil {
		err = errors.Tracef(
			"failed to convert field %s value `%v` type %T to %s : %w",
			fieldType.Name,
			logValue,
			logValue,
			fieldType.Type.String(),
			errors.Trace(err))
	}

	return nil
}

// setProtobufPointerField handles pointer fields by creating new instances
func setProtobufPointerField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	elemType := field.Type().Elem()

	// Special handling for timestamppb.Timestamp
	if elemType == reflect.TypeOf(timestamppb.Timestamp{}) {
		ts, err := protobufConvertToTimestamp(logValue)
		if err != nil {
			return errors.Trace(err)
		}

		if ts != nil {
			field.Set(reflect.ValueOf(ts))
		}

		return nil
	}

	// For primitive pointer types, create a new instance and set it
	newVal := reflect.New(elemType)
	err := setProtobufPrimitiveField(newVal.Elem(), fieldType, logValue)
	if err != nil {
		return errors.Trace(err)
	}

	field.Set(newVal)

	return nil
}

// setProtobufPrimitiveField handles non-pointer fields
func setProtobufPrimitiveField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	var err error
	switch field.Kind() {
	case reflect.String:
		err = setProtobufStringField(field, fieldType, logValue)
	case reflect.Int, reflect.Int32, reflect.Int64:
		err = setProtobufIntField(field, fieldType, logValue)
	case reflect.Uint, reflect.Uint32, reflect.Uint64:
		err = setProtobufUintField(field, fieldType, logValue)
	case reflect.Float64:
		err = setProtobufFloat64Field(field, fieldType, logValue)
	case reflect.Bool:
		err = setProtobufBoolField(field, fieldType, logValue)
	case reflect.Map:
		err = setProtobufMapField(field, fieldType, logValue)
	case reflect.Slice:
		err = setProtobufSliceField(field, fieldType, logValue)
	default:
		err = errors.TraceNew("unsupported field kind")
	}
	return errors.Trace(err)
}

func setProtobufStringField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	str, err := protobufConvertToString(logValue)
	if err != nil {
		return errors.Trace(err)
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

func setProtobufIntField(field reflect.Value, fieldType reflect.StructField, logValue any) error {

	// Because we extensively run on 64-bit architectures and protobuf
	// doesn't have the architecture switching int type, for consistency,
	// we always use int64 in our protos to represent int in go.

	val, err := protobufConvertToInt64(logValue)
	if err != nil {
		return errors.Trace(err)
	}

	field.SetInt(val)
	return nil
}

func setProtobufUintField(field reflect.Value, fieldType reflect.StructField, logValue any) error {

	// Because we extensively run on 64-bit architectures and protobuf
	// doesn't have the architecture switching int type, for consistency,
	// we always use uint64 in our protos to represent uint in go.

	val, err := protobufConvertToUint64(logValue)
	if err != nil {
		return errors.Trace(err)
	}

	field.SetUint(val)
	return nil
}

func setProtobufFloat64Field(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	val, err := protobufConvertToFloat64(logValue)
	if err != nil {
		return errors.Trace(err)
	}

	field.SetFloat(val)
	return nil
}

func setProtobufBoolField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	val, err := protobufConvertToBool(logValue)
	if err != nil {
		return errors.Trace(err)
	}

	field.SetBool(val)
	return nil
}

func setProtobufMapField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	mapValue, ok := logValue.(map[string]int64)
	if !ok {
		return errors.TraceNew("expected map[string]int64")
	}

	newMap := reflect.MakeMap(field.Type())

	for k, v := range mapValue {
		newMap.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(v))
	}

	field.Set(newMap)
	return nil
}

func setProtobufSliceField(field reflect.Value, fieldType reflect.StructField, logValue any) error {
	switch sliceValue := logValue.(type) {
	case []any:
		newSlice := make([]string, 0, len(sliceValue))
		for i, elem := range sliceValue {
			str, ok := elem.(string)
			if !ok {
				return errors.Tracef("slice element at index %d is not a string", i)
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
		return errors.TraceNew("unexpected slice type")
	}

	return nil
}

func protobufConvertToString(value any) (string, error) {
	var s string
	switch v := value.(type) {
	case string:
		s = v
	case fmt.Stringer:
		s = v.String()
	default:
		return "", errors.Tracef("cannot convert %T to string", value)
	}
	// Ensure the string is UTF-8, as required by proto.Marshal.
	return strings.ToValidUTF8(s, "\uFFFD"), nil
}

func protobufConvertToInt64(value any) (int64, error) {
	switch v := value.(type) {
	case int64:
		return v, nil

	case int:
		return int64(v), nil

	case int32:
		return int64(v), nil

	case string:
		if v == "" {
			return 0, errors.TraceNew("cannot convert empty string to int64")
		}

		return strconv.ParseInt(v, 10, 64)

	case float64:
		// Only allow conversion if it's a whole number
		if v == float64(int64(v)) {
			return int64(v), nil
		}

		return 0, errors.Tracef("float64 %f is not a whole number", v)

	case time.Duration:
		return int64(v), nil

	default:
		return 0, errors.Tracef("cannot convert %T to int64", value)
	}
}

func protobufConvertToUint64(value any) (uint64, error) {
	switch v := value.(type) {
	case uint64:
		return v, nil

	case uint:
		return uint64(v), nil

	case uint32:
		return uint64(v), nil

	case int:
		if v < 0 {
			return 0, errors.Tracef("cannot convert negative int %d to uint64", v)
		}

		return uint64(v), nil

	case int64:
		if v < 0 {
			return 0, errors.Tracef("cannot convert negative int64 %d to uint64", v)
		}

		return uint64(v), nil

	case string:
		if v == "" {
			return 0, errors.TraceNew("cannot convert empty string to uint64")
		}

		return strconv.ParseUint(v, 10, 64)

	default:
		return 0, errors.Tracef("cannot convert %T to uint64", value)
	}
}

func protobufConvertToFloat64(value any) (float64, error) {
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
			return 0, errors.TraceNew("cannot convert empty string to float64")
		}

		return strconv.ParseFloat(v, 64)

	default:
		return 0, errors.Tracef("cannot convert %T to float64", value)
	}
}

func protobufConvertToBool(value any) (bool, error) {
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
			return false, errors.Tracef("cannot convert string %q to bool", v)
		}
	case int:
		return v != 0, nil

	case int64:
		return v != 0, nil

	default:
		return false, fmt.Errorf("cannot convert %T to bool", value)
	}
}

func protobufConvertToTimestamp(value any) (*timestamppb.Timestamp, error) {
	switch v := value.(type) {
	case string:
		if v == "" || v == "None" {
			return nil, nil
		}

		var err error
		var t time.Time
		for _, format := range []string{
			time.RFC3339Nano,
			iso8601Date,
		} {
			if t, err = time.Parse(format, v); err == nil {
				break
			}
		}
		if err != nil {
			return nil, errors.Tracef("cannot parse timestamp string %q", v)
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
		return nil, errors.Tracef("cannot convert %T to timestamp", value)
	}
}

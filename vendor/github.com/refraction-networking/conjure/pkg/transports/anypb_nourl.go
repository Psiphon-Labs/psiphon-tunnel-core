package transports

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

// UnmarshalAnypbTo unmarshals the src anypb to dst without reading the src type url.
// Used to unmarshal TransportParams in the registration message for saving space from
// the type url so that the registration payload is small enough for the DNS registrar.
func UnmarshalAnypbTo(src *anypb.Any, dst protoreflect.ProtoMessage) error {
	if src == nil {
		// if a nil parameters source object is passed to us the result will also be nil and no
		// error will be returned.
		return nil
	}

	expected, err := anypb.New(dst)
	if err != nil {
		return fmt.Errorf("error reading src type: %v", err)
	}

	src.TypeUrl = strings.ReplaceAll(src.TypeUrl, "tapdance.", "proto.")

	if src.TypeUrl != "" && src.TypeUrl != expected.TypeUrl {
		return fmt.Errorf("incorrect non-empty TypeUrl: %v != %v", src.TypeUrl, expected.TypeUrl)
	}

	src.TypeUrl = expected.TypeUrl
	return anypb.UnmarshalTo(src, dst, proto.UnmarshalOptions{})
}

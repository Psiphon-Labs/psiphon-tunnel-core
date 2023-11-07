# Makefile for generating the language-specific protobuf modules

PROTOC		= protoc

SRC		= signalling.proto

GO_OUT		= signalling.pb.go
RUST_OUT	= signalling.rs
PYTHON_OUT	= signalling_pb2.py
RUST_OUT_PATH	= ../src/$(RUST_OUT)

default: $(RUST_OUT_PATH) $(GO_OUT)

$(GO_OUT):	$(SRC)
	$(PROTOC) $(SRC) --go_out . --go_opt=M"signalling.proto=./;proto" signalling.proto

$(RUST_OUT_PATH): $(SRC)
	$(PROTOC) $(SRC) --rust_out . && cp $(RUST_OUT) $(RUST_OUT_PATH)

$(PYTHON_OUT): $(SRC)
	$(PROTOC) -I . --python_out=. $(SRC)

clean:
	rm -f $(GO_OUT) $(RUST_OUT) $(RUST_OUT_PATH) $(PYTHON_OUT)

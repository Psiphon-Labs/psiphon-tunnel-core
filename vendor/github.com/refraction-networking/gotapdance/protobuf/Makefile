#
# github.com/protobuf/protoc-gen-go was recently deprecated in favor of 
# google.golang.org/protobuf/protoc-gen-go and there have been some changes to the interface.
# We are using protoc to generate golang as a package in a somewhat non-standard way and as such
# we have to specify some options. For more details see
# [here](https://developers.google.com/protocol-buffers/docs/reference/go-generated#package).
#
#	protoc --go_out=./ --go_opt=M"./signalling.proto=./;tdproto" signalling.proto \
#
# --go_out=./
#  		--go_out  == generate go files into the current directory
#
# --go_opt=M"signalling.proto=./;tdproto"
#  		--go_opt=			== use options for protoc-gen-go
#  		Msignalling.proto	== the structures defined by the protobuf at this path are used by the module defined here
#  		=./ 				== the module for importing related files is at ./ 
#  		;tdproto 			== use a custom package name (other than module name defined by package path, which we aren't using)
#
# signalling.proto == the file to compile using protoc
#
# --------------------------------------------------------------------------------------------------
#
# old command to compile the protobuf into a local file with package name tdproto
#
# 	protoc --go_out=import_path=tdproto:. signalling.proto \
	
all:
	protoc --go_out=./ --go_opt=M"signalling.proto=./;tdproto" signalling.proto

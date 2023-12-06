
protobuf specification for the messages from the station to the client
that tell the client which decoys to try to use, and the parameters
for those decoys.

The protobufs do not entirely describe the client<==>station protocol: these
protobufs are nested within a very primitive protocol. This outer protocol is
identical for both client=>station and station=>client. It consists of a
sequence of messages, each of which can be one of two types: raw app data (what
used to be MSG_DATA) or protobuf (StationToClient or ClientToStation, as
appropriate). There is no setup/teardown, just the messages.

The outer protocol is:
Each message is a 16-bit net-order int "TL" (type+len), followed by a data blob.
If TL is negative, the blob is pure app data, with length abs(TL).
If TL is positive, the blob is a protobuf, with length TL.
If TL is 0, then read the following 4 bytes. Those 4 bytes are a net-order u32.
            This u32 is the length of the blob, which begins after this u32.
            The blob is a protobuf.

We need this outer protocol because protobufs don't delimit themselves. This
outer protocol should never, ever change, given the flexibility of protobufs.
That's why we're willing to do funky stuff to optimize to the last bit.

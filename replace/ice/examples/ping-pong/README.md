# ping-pong

This example demonstrates how to connect two peers via ICE. Once started they send the current time between each other.

Currently this example exchanges candidates over a HTTP server running on localhost. In a real world setup `pion/ice` will typically
exchange auth and candidates via a signaling server.

## Instruction
### Run controlling

```sh
go run main.go -controlling
```


### Run controlled

```sh
go run main.go
```

### Press enter in both to start the connection!

You will see terminal output showing the messages being sent back and forth
```
Local Agent is controlled
Press 'Enter' when both processes have started
ICE Connection State has changed: Checking
ICE Connection State has changed: Connected
Sent: 'fCFXXlnGmXdYjOy'
Received: 'EpqTQYLQMUCjBDX'
Sent: 'yhgOtrufSfVmvrR'
Received: 'xYSTPxBPZKfgnFr'
```

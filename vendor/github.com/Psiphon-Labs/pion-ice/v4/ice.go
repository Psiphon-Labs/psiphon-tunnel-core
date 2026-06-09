// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

// ConnectionState is an enum showing the state of a ICE Connection.
type ConnectionState int

// List of supported States.
const (
	// ConnectionStateUnknown represents an unknown state.
	ConnectionStateUnknown ConnectionState = iota

	// ConnectionStateNew ICE agent is gathering addresses.
	ConnectionStateNew

	// ConnectionStateChecking ICE agent has been given local and remote candidates, and is attempting to find a match.
	ConnectionStateChecking

	// ConnectionStateConnected ICE agent has a pairing, but is still checking other pairs.
	ConnectionStateConnected

	// ConnectionStateCompleted ICE agent has finished.
	ConnectionStateCompleted

	// ConnectionStateFailed ICE agent never could successfully connect.
	ConnectionStateFailed

	// ConnectionStateDisconnected ICE agent connected successfully, but has entered a failed state.
	ConnectionStateDisconnected

	// ConnectionStateClosed ICE agent has finished and is no longer handling requests.
	ConnectionStateClosed
)

func (c ConnectionState) String() string {
	switch c {
	case ConnectionStateNew:
		return "New"
	case ConnectionStateChecking:
		return "Checking"
	case ConnectionStateConnected:
		return "Connected"
	case ConnectionStateCompleted:
		return "Completed"
	case ConnectionStateFailed:
		return "Failed"
	case ConnectionStateDisconnected:
		return "Disconnected"
	case ConnectionStateClosed:
		return "Closed"
	default:
		return "Invalid"
	}
}

// GatheringState describes the state of the candidate gathering process.
type GatheringState int

const (
	// GatheringStateUnknown represents an unknown state.
	GatheringStateUnknown GatheringState = iota

	// GatheringStateNew indicates candidate gathering is not yet started.
	GatheringStateNew

	// GatheringStateGathering indicates candidate gathering is ongoing.
	GatheringStateGathering

	// GatheringStateComplete indicates candidate gathering has been completed.
	GatheringStateComplete
)

func (t GatheringState) String() string {
	switch t {
	case GatheringStateNew:
		return "new"
	case GatheringStateGathering:
		return "gathering"
	case GatheringStateComplete:
		return "complete"
	default:
		return ErrUnknownType.Error()
	}
}

// ContinualGatheringPolicy defines the behavior for gathering ICE candidates.
type ContinualGatheringPolicy int

const (
	GatherOnce ContinualGatheringPolicy = iota
	GatherContinually
)

func (c ContinualGatheringPolicy) String() string {
	switch c {
	case GatherOnce:
		return "gather_once"
	case GatherContinually:
		return "gather_continually"
	default:
		return unknownStr
	}
}

const (
	unknownStr        = "unknown"
	relayProtocolDTLS = "dtls"
	relayProtocolTLS  = "tls"
)

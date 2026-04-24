// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"errors"

	"github.com/Psiphon-Labs/pion-ice/v4/internal/taskloop"
)

var (
	// ErrUnknownType indicates an error with Unknown info.
	ErrUnknownType = errors.New("Unknown")

	// ErrSchemeType indicates the scheme type could not be parsed.
	ErrSchemeType = errors.New("unknown scheme type")

	// ErrSTUNQuery indicates query arguments are provided in a STUN URL.
	ErrSTUNQuery = errors.New("queries not supported in STUN address")

	// ErrInvalidQuery indicates an malformed query is provided.
	ErrInvalidQuery = errors.New("invalid query")

	// ErrHost indicates malformed hostname is provided.
	ErrHost = errors.New("invalid hostname")

	// ErrPort indicates malformed port is provided.
	ErrPort = errors.New("invalid port")

	// ErrLocalUfragInsufficientBits indicates local username fragment insufficient bits are provided.
	// Have to be at least 24 bits long.
	ErrLocalUfragInsufficientBits = errors.New("local username fragment is less than 24 bits long")

	// ErrLocalPwdInsufficientBits indicates local password insufficient bits are provided.
	// Have to be at least 128 bits long.
	ErrLocalPwdInsufficientBits = errors.New("local password is less than 128 bits long")

	// ErrProtoType indicates an unsupported transport type was provided.
	ErrProtoType = errors.New("invalid transport protocol type")

	// ErrClosed indicates the agent is closed.
	ErrClosed = taskloop.ErrClosed

	// ErrNoCandidatePairs indicates agent does not have a valid candidate pair.
	ErrNoCandidatePairs = errors.New("no candidate pairs available")

	// ErrCanceledByCaller indicates agent connection was canceled by the caller.
	ErrCanceledByCaller = errors.New("connecting canceled by caller")

	// ErrMultipleStart indicates agent was started twice.
	ErrMultipleStart = errors.New("attempted to start agent twice")

	// ErrRemoteUfragEmpty indicates agent was started with an empty remote ufrag.
	ErrRemoteUfragEmpty = errors.New("remote ufrag is empty")

	// ErrRemotePwdEmpty indicates agent was started with an empty remote pwd.
	ErrRemotePwdEmpty = errors.New("remote pwd is empty")

	// ErrNoOnCandidateHandler indicates agent was started without OnCandidate.
	ErrNoOnCandidateHandler = errors.New("no OnCandidate provided")

	// ErrMultipleGatherAttempted indicates GatherCandidates has been called multiple times.
	ErrMultipleGatherAttempted = errors.New("attempting to gather candidates during gathering state")

	// ErrUsernameEmpty indicates agent was give TURN URL with an empty Username.
	ErrUsernameEmpty = errors.New("username is empty")

	// ErrPasswordEmpty indicates agent was give TURN URL with an empty Password.
	ErrPasswordEmpty = errors.New("password is empty")

	// ErrAddressParseFailed indicates we were unable to parse a candidate address.
	ErrAddressParseFailed = errors.New("failed to parse address")

	// ErrLiteUsingNonHostCandidates indicates non host candidates were selected for a lite agent.
	ErrLiteUsingNonHostCandidates = errors.New("lite agents must only use host candidates")

	// ErrUselessUrlsProvided indicates that one or more URL was provided to the agent but no host
	// candidate required them.
	ErrUselessUrlsProvided = errors.New("agent does not need URL with selected candidate types")

	// ErrUnsupportedNAT1To1IPCandidateType indicates that the specified NAT1To1IPCandidateType is
	// unsupported.
	//
	// Deprecated: use ErrUnsupportedAddressRewriteCandidateType instead. May still be returned
	// when configuring address rewrite rules while NAT1:1 compatibility remains.
	ErrUnsupportedNAT1To1IPCandidateType = errors.New("unsupported address rewrite candidate type")
	// ErrUnsupportedAddressRewriteCandidateType is an alias for ErrUnsupportedNAT1To1IPCandidateType.
	ErrUnsupportedAddressRewriteCandidateType = ErrUnsupportedNAT1To1IPCandidateType

	// ErrInvalidNAT1To1IPMapping indicates that the given 1:1 NAT IP mapping is invalid.
	//
	// Deprecated: use ErrInvalidAddressRewriteMapping instead. May still be returned by
	// WithAddressRewriteRules while NAT1:1 compatibility remains.
	ErrInvalidNAT1To1IPMapping = errors.New("invalid address rewrite mapping")
	// ErrInvalidAddressRewriteMapping is an alias for ErrInvalidNAT1To1IPMapping.
	ErrInvalidAddressRewriteMapping = ErrInvalidNAT1To1IPMapping

	// ErrExternalMappedIPNotFound in address rewrite mapping.
	//
	// Kept for compatibility; current code paths treat "no externals" via match state and
	// no longer return this error.
	ErrExternalMappedIPNotFound = errors.New("external mapped IP not found")

	// ErrMulticastDNSWithNAT1To1IPMapping indicates that the mDNS gathering cannot be used along
	// with 1:1 NAT IP mapping for host candidate.
	//
	// Deprecated: use ErrMulticastDNSWithAddressRewrite instead. May still be returned by
	// WithAddressRewriteRules while NAT1:1 compatibility remains.
	ErrMulticastDNSWithNAT1To1IPMapping = errors.New(
		"mDNS gathering cannot be used with address rewrite for host candidate",
	)
	// ErrMulticastDNSWithAddressRewrite is an alias for ErrMulticastDNSWithNAT1To1IPMapping.
	ErrMulticastDNSWithAddressRewrite = ErrMulticastDNSWithNAT1To1IPMapping

	// ErrIneffectiveNAT1To1IPMappingHost indicates that 1:1 NAT IP mapping for host candidate is
	// requested, but the host candidate type is disabled.
	//
	// Deprecated: use ErrIneffectiveAddressRewriteHost instead. May still be returned by
	// WithAddressRewriteRules while NAT1:1 compatibility remains.
	ErrIneffectiveNAT1To1IPMappingHost = errors.New("address rewrite for host candidate ineffective")
	// ErrIneffectiveAddressRewriteHost is an alias for ErrIneffectiveNAT1To1IPMappingHost.
	ErrIneffectiveAddressRewriteHost = ErrIneffectiveNAT1To1IPMappingHost

	// ErrIneffectiveNAT1To1IPMappingSrflx indicates that 1:1 NAT IP mapping for srflx candidate is
	// requested, but the srflx candidate type is disabled.
	//
	// Deprecated: use ErrIneffectiveAddressRewriteSrflx instead. May still be returned by
	// WithAddressRewriteRules while NAT1:1 compatibility remains.
	ErrIneffectiveNAT1To1IPMappingSrflx = errors.New("address rewrite for srflx candidate ineffective")
	// ErrIneffectiveAddressRewriteSrflx is an alias for ErrIneffectiveNAT1To1IPMappingSrflx.
	ErrIneffectiveAddressRewriteSrflx = ErrIneffectiveNAT1To1IPMappingSrflx

	// ErrInvalidMulticastDNSHostName indicates an invalid MulticastDNSHostName.
	ErrInvalidMulticastDNSHostName = errors.New(
		"invalid mDNS HostName, must end with .local and can only contain a single '.'",
	)

	// ErrRunCanceled indicates a run operation was canceled by its individual done.
	ErrRunCanceled = errors.New("run was canceled by done")

	// ErrTCPRemoteAddrAlreadyExists indicates we already have the connection with same remote addr.
	ErrTCPRemoteAddrAlreadyExists = errors.New("conn with same remote addr already exists")

	// ErrUnknownCandidateTyp indicates that a candidate had a unknown type value.
	ErrUnknownCandidateTyp = errors.New("unknown candidate typ")

	// ErrDetermineNetworkType indicates that the NetworkType was not able to be parsed.
	ErrDetermineNetworkType = errors.New("unable to determine networkType")

	// ErrOnlyControllingAgentCanRenominate indicates that only controlling agent can renominate.
	ErrOnlyControllingAgentCanRenominate = errors.New("only controlling agent can renominate")

	// ErrRenominationNotEnabled indicates that renomination is not enabled.
	ErrRenominationNotEnabled = errors.New("renomination is not enabled")

	// ErrCandidatePairNotFound indicates that candidate pair was not found.
	ErrCandidatePairNotFound = errors.New("candidate pair not found")

	// ErrCandidatePairNotSucceeded indicates that candidate pair is not in succeeded state.
	ErrCandidatePairNotSucceeded = errors.New("candidate pair not in succeeded state")

	// ErrInvalidNominationAttribute indicates an invalid nomination attribute type was provided.
	ErrInvalidNominationAttribute = errors.New("invalid nomination attribute type")

	// ErrInvalidNominationValueGenerator indicates a nil nomination value generator was provided.
	ErrInvalidNominationValueGenerator = errors.New("nomination value generator cannot be nil")

	// ErrInvalidNetworkMonitorInterval indicates an invalid network monitor interval was provided.
	ErrInvalidNetworkMonitorInterval = errors.New("network monitor interval must be greater than 0")

	// ErrAgentOptionNotUpdatable indicates an option cannot be updated after construction.
	ErrAgentOptionNotUpdatable = errors.New("option can only be set during agent construction")

	errAttributeTooShortICECandidate = errors.New("attribute not long enough to be ICE candidate")
	errClosingConnection             = errors.New("failed to close connection")
	errConnectionAddrAlreadyExist    = errors.New("connection with same remote address already exists")
	errGetXorMappedAddrResponse      = errors.New("failed to get XOR-MAPPED-ADDRESS response")
	errInvalidAddress                = errors.New("invalid address")
	errNoTCPMuxAvailable             = errors.New("no TCP mux is available")
	errNotImplemented                = errors.New("not implemented yet")
	errNoUDPMuxAvailable             = errors.New("no UDP mux is available")
	errNoXorAddrMapping              = errors.New("no address mapping")
	errParseFoundation               = errors.New("failed to parse foundation")
	errParseComponent                = errors.New("failed to parse component")
	errParsePort                     = errors.New("failed to parse port")
	errParsePriority                 = errors.New("failed to parse priority")
	errParseRelatedAddr              = errors.New("failed to parse related addresses")
	errParseExtension                = errors.New("failed to parse extension")
	errParseTCPType                  = errors.New("failed to parse TCP type")
	errUDPMuxDisabled                = errors.New("UDPMux is not enabled")
	errUnknownRole                   = errors.New("unknown role")
	errWrite                         = errors.New("failed to write")
	errWriteSTUNMessage              = errors.New("failed to send STUN message")
	errWriteSTUNMessageToIceConn     = errors.New("failed to write STUN message to ICE connection")
	errXORMappedAddrTimeout          = errors.New("timeout while waiting for XORMappedAddr")
	errFailedToCastUDPAddr           = errors.New("failed to cast net.Addr to net.UDPAddr")
	errInvalidIPAddress              = errors.New("invalid ip address")

	// UDPMuxDefault should not listen on unspecified address, but to keep backward compatibility, don't return error now.
	// will be used in the future.
	// errListenUnspecified             = errors.New("can't listen on unspecified address").
)

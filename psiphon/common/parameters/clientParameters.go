/*
 * Copyright (c) 2018, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
Package parameters implements dynamic, concurrency-safe parameters that
determine Psiphon client behavior.

Parameters include network timeouts, probabilities for actions, lists of
protocols, etc. Parameters are initialized with reasonable defaults. New
values may be applied, allowing the client to customized its parameters from
both a config file and tactics data. Sane minimum values are enforced.

Parameters may be read and updated concurrently. The read mechanism offers a
snapshot so that related parameters, such as two Ints representing a range; or
a more complex series of related parameters; may be read in an atomic and
consistent way. For example:

    p := clientParameters.Get()
    min := p.Int("Min")
    max := p.Int("Max")
    p = nil

For long-running operations, it is recommended to set any pointer to the
snapshot to nil to allow garbage collection of old snaphots in cases where the
parameters change.

In general, client parameters should be read as close to the point of use as
possible to ensure that dynamic changes to the parameter values take effect.

For duration parameters, time.ParseDuration-compatible string values are
supported when applying new values. This allows specifying durations as, for
example, "100ms" or "24h".

Values read from the parameters are not deep copies and must be treated as
read-only.
*/
package parameters

import (
	"encoding/json"
	"net/http"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"golang.org/x/net/bpf"
)

const (
	NetworkLatencyMultiplier                         = "NetworkLatencyMultiplier"
	NetworkLatencyMultiplierMin                      = "NetworkLatencyMultiplierMin"
	NetworkLatencyMultiplierMax                      = "NetworkLatencyMultiplierMax"
	NetworkLatencyMultiplierLambda                   = "NetworkLatencyMultiplierLambda"
	TacticsWaitPeriod                                = "TacticsWaitPeriod"
	TacticsRetryPeriod                               = "TacticsRetryPeriod"
	TacticsRetryPeriodJitter                         = "TacticsRetryPeriodJitter"
	TacticsTimeout                                   = "TacticsTimeout"
	ConnectionWorkerPoolSize                         = "ConnectionWorkerPoolSize"
	TunnelConnectTimeout                             = "TunnelConnectTimeout"
	EstablishTunnelTimeout                           = "EstablishTunnelTimeout"
	EstablishTunnelWorkTime                          = "EstablishTunnelWorkTime"
	EstablishTunnelPausePeriod                       = "EstablishTunnelPausePeriod"
	EstablishTunnelPausePeriodJitter                 = "EstablishTunnelPausePeriodJitter"
	EstablishTunnelServerAffinityGracePeriod         = "EstablishTunnelServerAffinityGracePeriod"
	StaggerConnectionWorkersPeriod                   = "StaggerConnectionWorkersPeriod"
	StaggerConnectionWorkersJitter                   = "StaggerConnectionWorkersJitter"
	LimitIntensiveConnectionWorkers                  = "LimitIntensiveConnectionWorkers"
	IgnoreHandshakeStatsRegexps                      = "IgnoreHandshakeStatsRegexps"
	PrioritizeTunnelProtocolsProbability             = "PrioritizeTunnelProtocolsProbability"
	PrioritizeTunnelProtocols                        = "PrioritizeTunnelProtocols"
	PrioritizeTunnelProtocolsCandidateCount          = "PrioritizeTunnelProtocolsCandidateCount"
	InitialLimitTunnelProtocolsProbability           = "InitialLimitTunnelProtocolsProbability"
	InitialLimitTunnelProtocols                      = "InitialLimitTunnelProtocols"
	InitialLimitTunnelProtocolsCandidateCount        = "InitialLimitTunnelProtocolsCandidateCount"
	LimitTunnelProtocolsProbability                  = "LimitTunnelProtocolsProbability"
	LimitTunnelProtocols                             = "LimitTunnelProtocols"
	LimitTLSProfilesProbability                      = "LimitTLSProfilesProbability"
	LimitTLSProfiles                                 = "LimitTLSProfiles"
	UseOnlyCustomTLSProfiles                         = "UseOnlyCustomTLSProfiles"
	CustomTLSProfiles                                = "CustomTLSProfiles"
	SelectRandomizedTLSProfileProbability            = "SelectRandomizedTLSProfileProbability"
	NoDefaultTLSSessionIDProbability                 = "NoDefaultTLSSessionIDProbability"
	DisableFrontingProviderTLSProfiles               = "DisableFrontingProviderTLSProfiles"
	LimitQUICVersionsProbability                     = "LimitQUICVersionsProbability"
	LimitQUICVersions                                = "LimitQUICVersions"
	DisableFrontingProviderQUICVersions              = "DisableFrontingProviderQUICVersions"
	FragmentorProbability                            = "FragmentorProbability"
	FragmentorLimitProtocols                         = "FragmentorLimitProtocols"
	FragmentorMinTotalBytes                          = "FragmentorMinTotalBytes"
	FragmentorMaxTotalBytes                          = "FragmentorMaxTotalBytes"
	FragmentorMinWriteBytes                          = "FragmentorMinWriteBytes"
	FragmentorMaxWriteBytes                          = "FragmentorMaxWriteBytes"
	FragmentorMinDelay                               = "FragmentorMinDelay"
	FragmentorMaxDelay                               = "FragmentorMaxDelay"
	FragmentorDownstreamProbability                  = "FragmentorDownstreamProbability"
	FragmentorDownstreamLimitProtocols               = "FragmentorDownstreamLimitProtocols"
	FragmentorDownstreamMinTotalBytes                = "FragmentorDownstreamMinTotalBytes"
	FragmentorDownstreamMaxTotalBytes                = "FragmentorDownstreamMaxTotalBytes"
	FragmentorDownstreamMinWriteBytes                = "FragmentorDownstreamMinWriteBytes"
	FragmentorDownstreamMaxWriteBytes                = "FragmentorDownstreamMaxWriteBytes"
	FragmentorDownstreamMinDelay                     = "FragmentorDownstreamMinDelay"
	FragmentorDownstreamMaxDelay                     = "FragmentorDownstreamMaxDelay"
	ObfuscatedSSHMinPadding                          = "ObfuscatedSSHMinPadding"
	ObfuscatedSSHMaxPadding                          = "ObfuscatedSSHMaxPadding"
	TunnelOperateShutdownTimeout                     = "TunnelOperateShutdownTimeout"
	TunnelPortForwardDialTimeout                     = "TunnelPortForwardDialTimeout"
	PacketTunnelReadTimeout                          = "PacketTunnelReadTimeout"
	TunnelRateLimits                                 = "TunnelRateLimits"
	AdditionalCustomHeaders                          = "AdditionalCustomHeaders"
	SpeedTestPaddingMinBytes                         = "SpeedTestPaddingMinBytes"
	SpeedTestPaddingMaxBytes                         = "SpeedTestPaddingMaxBytes"
	SpeedTestMaxSampleCount                          = "SpeedTestMaxSampleCount"
	SSHKeepAliveSpeedTestSampleProbability           = "SSHKeepAliveSpeedTestSampleProbability"
	SSHKeepAlivePaddingMinBytes                      = "SSHKeepAlivePaddingMinBytes"
	SSHKeepAlivePaddingMaxBytes                      = "SSHKeepAlivePaddingMaxBytes"
	SSHKeepAlivePeriodMin                            = "SSHKeepAlivePeriodMin"
	SSHKeepAlivePeriodMax                            = "SSHKeepAlivePeriodMax"
	SSHKeepAlivePeriodicTimeout                      = "SSHKeepAlivePeriodicTimeout"
	SSHKeepAlivePeriodicInactivePeriod               = "SSHKeepAlivePeriodicInactivePeriod"
	SSHKeepAliveProbeTimeout                         = "SSHKeepAliveProbeTimeout"
	SSHKeepAliveProbeInactivePeriod                  = "SSHKeepAliveProbeInactivePeriod"
	SSHKeepAliveNetworkConnectivityPollingPeriod     = "SSHKeepAliveNetworkConnectivityPollingPeriod"
	SSHKeepAliveResetOnFailureProbability            = "SSHKeepAliveResetOnFailureProbability"
	HTTPProxyOriginServerTimeout                     = "HTTPProxyOriginServerTimeout"
	HTTPProxyMaxIdleConnectionsPerHost               = "HTTPProxyMaxIdleConnectionsPerHost"
	FetchRemoteServerListTimeout                     = "FetchRemoteServerListTimeout"
	FetchRemoteServerListRetryPeriod                 = "FetchRemoteServerListRetryPeriod"
	FetchRemoteServerListStalePeriod                 = "FetchRemoteServerListStalePeriod"
	RemoteServerListSignaturePublicKey               = "RemoteServerListSignaturePublicKey"
	RemoteServerListURLs                             = "RemoteServerListURLs"
	ObfuscatedServerListRootURLs                     = "ObfuscatedServerListRootURLs"
	PsiphonAPIRequestTimeout                         = "PsiphonAPIRequestTimeout"
	PsiphonAPIStatusRequestPeriodMin                 = "PsiphonAPIStatusRequestPeriodMin"
	PsiphonAPIStatusRequestPeriodMax                 = "PsiphonAPIStatusRequestPeriodMax"
	PsiphonAPIStatusRequestShortPeriodMin            = "PsiphonAPIStatusRequestShortPeriodMin"
	PsiphonAPIStatusRequestShortPeriodMax            = "PsiphonAPIStatusRequestShortPeriodMax"
	PsiphonAPIStatusRequestPaddingMinBytes           = "PsiphonAPIStatusRequestPaddingMinBytes"
	PsiphonAPIStatusRequestPaddingMaxBytes           = "PsiphonAPIStatusRequestPaddingMaxBytes"
	PsiphonAPIPersistentStatsMaxCount                = "PsiphonAPIPersistentStatsMaxCount"
	PsiphonAPIConnectedRequestPeriod                 = "PsiphonAPIConnectedRequestPeriod"
	PsiphonAPIConnectedRequestRetryPeriod            = "PsiphonAPIConnectedRequestRetryPeriod"
	FetchSplitTunnelRoutesTimeout                    = "FetchSplitTunnelRoutesTimeout"
	SplitTunnelRoutesURLFormat                       = "SplitTunnelRoutesURLFormat"
	SplitTunnelRoutesSignaturePublicKey              = "SplitTunnelRoutesSignaturePublicKey"
	SplitTunnelDNSServer                             = "SplitTunnelDNSServer"
	FetchUpgradeTimeout                              = "FetchUpgradeTimeout"
	FetchUpgradeRetryPeriod                          = "FetchUpgradeRetryPeriod"
	FetchUpgradeStalePeriod                          = "FetchUpgradeStalePeriod"
	UpgradeDownloadURLs                              = "UpgradeDownloadURLs"
	UpgradeDownloadClientVersionHeader               = "UpgradeDownloadClientVersionHeader"
	TotalBytesTransferredNoticePeriod                = "TotalBytesTransferredNoticePeriod"
	MeekDialDomainsOnly                              = "MeekDialDomainsOnly"
	MeekLimitBufferSizes                             = "MeekLimitBufferSizes"
	MeekCookieMaxPadding                             = "MeekCookieMaxPadding"
	MeekFullReceiveBufferLength                      = "MeekFullReceiveBufferLength"
	MeekReadPayloadChunkLength                       = "MeekReadPayloadChunkLength"
	MeekLimitedFullReceiveBufferLength               = "MeekLimitedFullReceiveBufferLength"
	MeekLimitedReadPayloadChunkLength                = "MeekLimitedReadPayloadChunkLength"
	MeekMinPollInterval                              = "MeekMinPollInterval"
	MeekMinPollIntervalJitter                        = "MeekMinPollIntervalJitter"
	MeekMaxPollInterval                              = "MeekMaxPollInterval"
	MeekMaxPollIntervalJitter                        = "MeekMaxPollIntervalJitter"
	MeekPollIntervalMultiplier                       = "MeekPollIntervalMultiplier"
	MeekPollIntervalJitter                           = "MeekPollIntervalJitter"
	MeekApplyPollIntervalMultiplierProbability       = "MeekApplyPollIntervalMultiplierProbability"
	MeekRoundTripRetryDeadline                       = "MeekRoundTripRetryDeadline"
	MeekRoundTripRetryMinDelay                       = "MeekRoundTripRetryMinDelay"
	MeekRoundTripRetryMaxDelay                       = "MeekRoundTripRetryMaxDelay"
	MeekRoundTripRetryMultiplier                     = "MeekRoundTripRetryMultiplier"
	MeekRoundTripTimeout                             = "MeekRoundTripTimeout"
	MeekTrafficShapingProbability                    = "MeekTrafficShapingProbability"
	MeekTrafficShapingLimitProtocols                 = "MeekTrafficShapingLimitProtocols"
	MeekMinTLSPadding                                = "MeekMinTLSPadding"
	MeekMaxTLSPadding                                = "MeekMaxTLSPadding"
	MeekMinLimitRequestPayloadLength                 = "MeekMinLimitRequestPayloadLength"
	MeekMaxLimitRequestPayloadLength                 = "MeekMaxLimitRequestPayloadLength"
	MeekRedialTLSProbability                         = "MeekRedialTLSProbability"
	TransformHostNameProbability                     = "TransformHostNameProbability"
	PickUserAgentProbability                         = "PickUserAgentProbability"
	LivenessTestMinUpstreamBytes                     = "LivenessTestMinUpstreamBytes"
	LivenessTestMaxUpstreamBytes                     = "LivenessTestMaxUpstreamBytes"
	LivenessTestMinDownstreamBytes                   = "LivenessTestMinDownstreamBytes"
	LivenessTestMaxDownstreamBytes                   = "LivenessTestMaxDownstreamBytes"
	ReplayCandidateCount                             = "ReplayCandidateCount"
	ReplayDialParametersTTL                          = "ReplayDialParametersTTL"
	ReplayTargetUpstreamBytes                        = "ReplayTargetUpstreamBytes"
	ReplayTargetDownstreamBytes                      = "ReplayTargetDownstreamBytes"
	ReplayTargetTunnelDuration                       = "ReplayTargetTunnelDuration"
	ReplayBPF                                        = "ReplayBPF"
	ReplaySSH                                        = "ReplaySSH"
	ReplayObfuscatorPadding                          = "ReplayObfuscatorPadding"
	ReplayFragmentor                                 = "ReplayFragmentor"
	ReplayTLSProfile                                 = "ReplayTLSProfile"
	ReplayRandomizedTLSProfile                       = "ReplayRandomizedTLSProfile"
	ReplayFronting                                   = "ReplayFronting"
	ReplayHostname                                   = "ReplayHostname"
	ReplayQUICVersion                                = "ReplayQUICVersion"
	ReplayObfuscatedQUIC                             = "ReplayObfuscatedQUIC"
	ReplayLivenessTest                               = "ReplayLivenessTest"
	ReplayUserAgent                                  = "ReplayUserAgent"
	ReplayAPIRequestPadding                          = "ReplayAPIRequestPadding"
	ReplayLaterRoundMoveToFrontProbability           = "ReplayLaterRoundMoveToFrontProbability"
	ReplayRetainFailedProbability                    = "ReplayRetainFailedProbability"
	APIRequestUpstreamPaddingMinBytes                = "APIRequestUpstreamPaddingMinBytes"
	APIRequestUpstreamPaddingMaxBytes                = "APIRequestUpstreamPaddingMaxBytes"
	APIRequestDownstreamPaddingMinBytes              = "APIRequestDownstreamPaddingMinBytes"
	APIRequestDownstreamPaddingMaxBytes              = "APIRequestDownstreamPaddingMaxBytes"
	PersistentStatsMaxStoreRecords                   = "PersistentStatsMaxStoreRecords"
	PersistentStatsMaxSendBytes                      = "PersistentStatsMaxSendBytes"
	RecordRemoteServerListPersistentStatsProbability = "RecordRemoteServerListPersistentStatsProbability"
	RecordFailedTunnelPersistentStatsProbability     = "RecordFailedTunnelPersistentStatsProbability"
	ServerEntryMinimumAgeForPruning                  = "ServerEntryMinimumAgeForPruning"
	ApplicationParametersProbability                 = "ApplicationParametersProbability"
	ApplicationParameters                            = "ApplicationParameters"
	BPFServerTCPProgram                              = "BPFServerTCPProgram"
	BPFServerTCPProbability                          = "BPFServerTCPProbability"
	BPFClientTCPProgram                              = "BPFClientTCPProgram"
	BPFClientTCPProbability                          = "BPFClientTCPProbability"
)

const (
	useNetworkLatencyMultiplier = 1
	serverSideOnly              = 2
)

// defaultClientParameters specifies the type, default value, and minimum
// value for all dynamically configurable client parameters.
//
// Do not change the names or types of existing values, as that can break
// client logic or cause parameters to not be applied.
//
// Minimum values are a fail-safe for cases where lower values would break the
// client logic. For example, setting a ConnectionWorkerPoolSize of 0 would
// make the client never connect.
var defaultClientParameters = map[string]struct {
	value   interface{}
	minimum interface{}
	flags   int32
}{
	// NetworkLatencyMultiplier defaults to 0, meaning off. But when set, it
	// must be a multiplier >= 1.

	NetworkLatencyMultiplier:       {value: 0.0, minimum: 1.0},
	NetworkLatencyMultiplierMin:    {value: 1.0, minimum: 1.0},
	NetworkLatencyMultiplierMax:    {value: 3.0, minimum: 1.0},
	NetworkLatencyMultiplierLambda: {value: 2.0, minimum: 0.001},

	TacticsWaitPeriod:        {value: 10 * time.Second, minimum: 0 * time.Second, flags: useNetworkLatencyMultiplier},
	TacticsRetryPeriod:       {value: 5 * time.Second, minimum: 1 * time.Millisecond},
	TacticsRetryPeriodJitter: {value: 0.3, minimum: 0.0},
	TacticsTimeout:           {value: 2 * time.Minute, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},

	ConnectionWorkerPoolSize:                 {value: 10, minimum: 1},
	TunnelConnectTimeout:                     {value: 20 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	EstablishTunnelTimeout:                   {value: 300 * time.Second, minimum: time.Duration(0)},
	EstablishTunnelWorkTime:                  {value: 60 * time.Second, minimum: 1 * time.Second},
	EstablishTunnelPausePeriod:               {value: 5 * time.Second, minimum: 1 * time.Millisecond},
	EstablishTunnelPausePeriodJitter:         {value: 0.1, minimum: 0.0},
	EstablishTunnelServerAffinityGracePeriod: {value: 1 * time.Second, minimum: time.Duration(0), flags: useNetworkLatencyMultiplier},
	StaggerConnectionWorkersPeriod:           {value: time.Duration(0), minimum: time.Duration(0)},
	StaggerConnectionWorkersJitter:           {value: 0.1, minimum: 0.0},
	LimitIntensiveConnectionWorkers:          {value: 0, minimum: 0},
	IgnoreHandshakeStatsRegexps:              {value: false},
	TunnelOperateShutdownTimeout:             {value: 1 * time.Second, minimum: 1 * time.Millisecond, flags: useNetworkLatencyMultiplier},
	TunnelPortForwardDialTimeout:             {value: 10 * time.Second, minimum: 1 * time.Millisecond, flags: useNetworkLatencyMultiplier},
	PacketTunnelReadTimeout:                  {value: 10 * time.Second, minimum: 1 * time.Millisecond, flags: useNetworkLatencyMultiplier},
	TunnelRateLimits:                         {value: common.RateLimits{}},

	// PrioritizeTunnelProtocols parameters are obsoleted by InitialLimitTunnelProtocols.
	// TODO: remove once no longer required for older clients.
	PrioritizeTunnelProtocolsProbability:    {value: 1.0, minimum: 0.0},
	PrioritizeTunnelProtocols:               {value: protocol.TunnelProtocols{}},
	PrioritizeTunnelProtocolsCandidateCount: {value: 10, minimum: 0},

	InitialLimitTunnelProtocolsProbability:    {value: 1.0, minimum: 0.0},
	InitialLimitTunnelProtocols:               {value: protocol.TunnelProtocols{}},
	InitialLimitTunnelProtocolsCandidateCount: {value: 0, minimum: 0},

	LimitTunnelProtocolsProbability: {value: 1.0, minimum: 0.0},
	LimitTunnelProtocols:            {value: protocol.TunnelProtocols{}},

	LimitTLSProfilesProbability:           {value: 1.0, minimum: 0.0},
	LimitTLSProfiles:                      {value: protocol.TLSProfiles{}},
	UseOnlyCustomTLSProfiles:              {value: false},
	CustomTLSProfiles:                     {value: protocol.CustomTLSProfiles{}},
	SelectRandomizedTLSProfileProbability: {value: 0.25, minimum: 0.0},
	NoDefaultTLSSessionIDProbability:      {value: 0.5, minimum: 0.0},
	DisableFrontingProviderTLSProfiles:    {value: protocol.LabeledTLSProfiles{}},

	LimitQUICVersionsProbability:        {value: 1.0, minimum: 0.0},
	LimitQUICVersions:                   {value: protocol.QUICVersions{}},
	DisableFrontingProviderQUICVersions: {value: protocol.LabeledQUICVersions{}},

	FragmentorProbability:              {value: 0.5, minimum: 0.0},
	FragmentorLimitProtocols:           {value: protocol.TunnelProtocols{}},
	FragmentorMinTotalBytes:            {value: 0, minimum: 0},
	FragmentorMaxTotalBytes:            {value: 0, minimum: 0},
	FragmentorMinWriteBytes:            {value: 1, minimum: 1},
	FragmentorMaxWriteBytes:            {value: 1500, minimum: 1},
	FragmentorMinDelay:                 {value: time.Duration(0), minimum: time.Duration(0)},
	FragmentorMaxDelay:                 {value: 10 * time.Millisecond, minimum: time.Duration(0)},
	FragmentorDownstreamProbability:    {value: 0.5, minimum: 0.0, flags: serverSideOnly},
	FragmentorDownstreamLimitProtocols: {value: protocol.TunnelProtocols{}, flags: serverSideOnly},
	FragmentorDownstreamMinTotalBytes:  {value: 0, minimum: 0, flags: serverSideOnly},
	FragmentorDownstreamMaxTotalBytes:  {value: 0, minimum: 0, flags: serverSideOnly},
	FragmentorDownstreamMinWriteBytes:  {value: 1, minimum: 1, flags: serverSideOnly},
	FragmentorDownstreamMaxWriteBytes:  {value: 1500, minimum: 1, flags: serverSideOnly},
	FragmentorDownstreamMinDelay:       {value: time.Duration(0), minimum: time.Duration(0), flags: serverSideOnly},
	FragmentorDownstreamMaxDelay:       {value: 10 * time.Millisecond, minimum: time.Duration(0), flags: serverSideOnly},

	// The Psiphon server will reject obfuscated SSH seed messages with
	// padding greater than OBFUSCATE_MAX_PADDING.
	// obfuscator.NewClientObfuscator will ignore invalid min/max padding
	// configurations.

	ObfuscatedSSHMinPadding: {value: 0, minimum: 0},
	ObfuscatedSSHMaxPadding: {value: obfuscator.OBFUSCATE_MAX_PADDING, minimum: 0},

	AdditionalCustomHeaders: {value: make(http.Header)},

	// Speed test and SSH keep alive padding is intended to frustrate
	// fingerprinting and should not exceed ~1 IP packet size.
	//
	// Currently, each serialized speed test sample, populated with real
	// values, is approximately 100 bytes. All SpeedTestMaxSampleCount samples
	// are loaded into memory are sent as API inputs.

	SpeedTestPaddingMinBytes: {value: 0, minimum: 0},
	SpeedTestPaddingMaxBytes: {value: 256, minimum: 0},
	SpeedTestMaxSampleCount:  {value: 25, minimum: 1},

	// The Psiphon server times out inactive tunnels after 5 minutes, so this
	// is a soft max for SSHKeepAlivePeriodMax.

	SSHKeepAliveSpeedTestSampleProbability:       {value: 0.5, minimum: 0.0},
	SSHKeepAlivePaddingMinBytes:                  {value: 0, minimum: 0},
	SSHKeepAlivePaddingMaxBytes:                  {value: 256, minimum: 0},
	SSHKeepAlivePeriodMin:                        {value: 1 * time.Minute, minimum: 1 * time.Second},
	SSHKeepAlivePeriodMax:                        {value: 2 * time.Minute, minimum: 1 * time.Second},
	SSHKeepAlivePeriodicTimeout:                  {value: 30 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	SSHKeepAlivePeriodicInactivePeriod:           {value: 10 * time.Second, minimum: 1 * time.Second},
	SSHKeepAliveProbeTimeout:                     {value: 5 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	SSHKeepAliveProbeInactivePeriod:              {value: 10 * time.Second, minimum: 1 * time.Second},
	SSHKeepAliveNetworkConnectivityPollingPeriod: {value: 500 * time.Millisecond, minimum: 1 * time.Millisecond},
	SSHKeepAliveResetOnFailureProbability:        {value: 0.0, minimum: 0.0},

	HTTPProxyOriginServerTimeout:       {value: 15 * time.Second, minimum: time.Duration(0), flags: useNetworkLatencyMultiplier},
	HTTPProxyMaxIdleConnectionsPerHost: {value: 50, minimum: 0},

	FetchRemoteServerListTimeout:       {value: 30 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	FetchRemoteServerListRetryPeriod:   {value: 30 * time.Second, minimum: 1 * time.Millisecond},
	FetchRemoteServerListStalePeriod:   {value: 6 * time.Hour, minimum: 1 * time.Hour},
	RemoteServerListSignaturePublicKey: {value: ""},
	RemoteServerListURLs:               {value: DownloadURLs{}},
	ObfuscatedServerListRootURLs:       {value: DownloadURLs{}},

	PsiphonAPIRequestTimeout: {value: 20 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},

	PsiphonAPIStatusRequestPeriodMin:      {value: 5 * time.Minute, minimum: 1 * time.Second},
	PsiphonAPIStatusRequestPeriodMax:      {value: 10 * time.Minute, minimum: 1 * time.Second},
	PsiphonAPIStatusRequestShortPeriodMin: {value: 5 * time.Second, minimum: 1 * time.Second},
	PsiphonAPIStatusRequestShortPeriodMax: {value: 10 * time.Second, minimum: 1 * time.Second},
	// PsiphonAPIPersistentStatsMaxCount parameter is obsoleted by PersistentStatsMaxSendBytes.
	// TODO: remove once no longer required for older clients.
	PsiphonAPIPersistentStatsMaxCount: {value: 100, minimum: 1},
	// PsiphonAPIStatusRequestPadding parameters are obsoleted by APIRequestUp/DownstreamPadding.
	// TODO: remove once no longer required for older clients.
	PsiphonAPIStatusRequestPaddingMinBytes: {value: 0, minimum: 0},
	PsiphonAPIStatusRequestPaddingMaxBytes: {value: 256, minimum: 0},

	PsiphonAPIConnectedRequestRetryPeriod: {value: 5 * time.Second, minimum: 1 * time.Millisecond},

	FetchSplitTunnelRoutesTimeout:       {value: 60 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	SplitTunnelRoutesURLFormat:          {value: ""},
	SplitTunnelRoutesSignaturePublicKey: {value: ""},
	SplitTunnelDNSServer:                {value: ""},

	FetchUpgradeTimeout:                {value: 60 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	FetchUpgradeRetryPeriod:            {value: 30 * time.Second, minimum: 1 * time.Millisecond},
	FetchUpgradeStalePeriod:            {value: 6 * time.Hour, minimum: 1 * time.Hour},
	UpgradeDownloadURLs:                {value: DownloadURLs{}},
	UpgradeDownloadClientVersionHeader: {value: ""},

	TotalBytesTransferredNoticePeriod: {value: 5 * time.Minute, minimum: 1 * time.Second},

	// The meek server times out inactive sessions after 45 seconds, so this
	// is a soft max for MeekMaxPollInterval,  MeekRoundTripTimeout, and
	// MeekRoundTripRetryDeadline.
	//
	// MeekCookieMaxPadding cannot exceed common.OBFUSCATE_SEED_LENGTH.
	//
	// MeekMinTLSPadding/MeekMinTLSPadding are subject to TLS server limitations.
	//
	// MeekMinLimitRequestPayloadLength/MeekMaxLimitRequestPayloadLength
	// cannot exceed server.MEEK_MAX_REQUEST_PAYLOAD_LENGTH.

	MeekDialDomainsOnly:                        {value: false},
	MeekLimitBufferSizes:                       {value: false},
	MeekCookieMaxPadding:                       {value: 256, minimum: 0},
	MeekFullReceiveBufferLength:                {value: 4194304, minimum: 1024},
	MeekReadPayloadChunkLength:                 {value: 65536, minimum: 1024},
	MeekLimitedFullReceiveBufferLength:         {value: 131072, minimum: 1024},
	MeekLimitedReadPayloadChunkLength:          {value: 4096, minimum: 1024},
	MeekMinPollInterval:                        {value: 100 * time.Millisecond, minimum: 1 * time.Millisecond},
	MeekMinPollIntervalJitter:                  {value: 0.3, minimum: 0.0},
	MeekMaxPollInterval:                        {value: 5 * time.Second, minimum: 1 * time.Millisecond},
	MeekMaxPollIntervalJitter:                  {value: 0.1, minimum: 0.0},
	MeekPollIntervalMultiplier:                 {value: 1.5, minimum: 0.0},
	MeekPollIntervalJitter:                     {value: 0.1, minimum: 0.0},
	MeekApplyPollIntervalMultiplierProbability: {value: 0.5},
	MeekRoundTripRetryDeadline:                 {value: 5 * time.Second, minimum: 1 * time.Millisecond, flags: useNetworkLatencyMultiplier},
	MeekRoundTripRetryMinDelay:                 {value: 50 * time.Millisecond, minimum: time.Duration(0)},
	MeekRoundTripRetryMaxDelay:                 {value: 1 * time.Second, minimum: time.Duration(0)},
	MeekRoundTripRetryMultiplier:               {value: 2.0, minimum: 0.0},
	MeekRoundTripTimeout:                       {value: 20 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},

	MeekTrafficShapingProbability:    {value: 1.0, minimum: 0.0},
	MeekTrafficShapingLimitProtocols: {value: protocol.TunnelProtocols{}},
	MeekMinTLSPadding:                {value: 0, minimum: 0},
	MeekMaxTLSPadding:                {value: 0, minimum: 0},
	MeekMinLimitRequestPayloadLength: {value: 65536, minimum: 1},
	MeekMaxLimitRequestPayloadLength: {value: 65536, minimum: 1},
	MeekRedialTLSProbability:         {value: 0.0, minimum: 0.0},

	TransformHostNameProbability: {value: 0.5, minimum: 0.0},
	PickUserAgentProbability:     {value: 0.5, minimum: 0.0},

	LivenessTestMinUpstreamBytes:   {value: 0, minimum: 0},
	LivenessTestMaxUpstreamBytes:   {value: 0, minimum: 0},
	LivenessTestMinDownstreamBytes: {value: 0, minimum: 0},
	LivenessTestMaxDownstreamBytes: {value: 0, minimum: 0},

	ReplayCandidateCount:                   {value: 10, minimum: -1},
	ReplayDialParametersTTL:                {value: 24 * time.Hour, minimum: time.Duration(0)},
	ReplayTargetUpstreamBytes:              {value: 0, minimum: 0},
	ReplayTargetDownstreamBytes:            {value: 0, minimum: 0},
	ReplayTargetTunnelDuration:             {value: 1 * time.Second, minimum: time.Duration(0)},
	ReplayBPF:                              {value: true},
	ReplaySSH:                              {value: true},
	ReplayObfuscatorPadding:                {value: true},
	ReplayFragmentor:                       {value: true},
	ReplayTLSProfile:                       {value: true},
	ReplayRandomizedTLSProfile:             {value: true},
	ReplayFronting:                         {value: true},
	ReplayHostname:                         {value: true},
	ReplayQUICVersion:                      {value: true},
	ReplayObfuscatedQUIC:                   {value: true},
	ReplayLivenessTest:                     {value: true},
	ReplayUserAgent:                        {value: true},
	ReplayAPIRequestPadding:                {value: true},
	ReplayLaterRoundMoveToFrontProbability: {value: 0.0, minimum: 0.0},
	ReplayRetainFailedProbability:          {value: 0.5, minimum: 0.0},

	APIRequestUpstreamPaddingMinBytes:   {value: 0, minimum: 0},
	APIRequestUpstreamPaddingMaxBytes:   {value: 1024, minimum: 0},
	APIRequestDownstreamPaddingMinBytes: {value: 0, minimum: 0},
	APIRequestDownstreamPaddingMaxBytes: {value: 1024, minimum: 0},

	PersistentStatsMaxStoreRecords:                   {value: 200, minimum: 1},
	PersistentStatsMaxSendBytes:                      {value: 65536, minimum: 1},
	RecordRemoteServerListPersistentStatsProbability: {value: 1.0, minimum: 0.0},
	RecordFailedTunnelPersistentStatsProbability:     {value: 0.0, minimum: 0.0},

	ServerEntryMinimumAgeForPruning: {value: 7 * 24 * time.Hour, minimum: 24 * time.Hour},

	ApplicationParametersProbability: {value: 1.0, minimum: 0.0},
	ApplicationParameters:            {value: KeyValues{}},

	BPFServerTCPProgram:     {value: (*BPFProgramSpec)(nil)},
	BPFServerTCPProbability: {value: 0.5, minimum: 0.0},
	BPFClientTCPProgram:     {value: (*BPFProgramSpec)(nil)},
	BPFClientTCPProbability: {value: 0.5, minimum: 0.0},
}

// IsServerSideOnly indicates if the parameter specified by name is used
// server-side only.
func IsServerSideOnly(name string) bool {
	defaultParameter, ok := defaultClientParameters[name]
	return ok && (defaultParameter.flags&serverSideOnly) != 0
}

// ClientParameters is a set of client parameters. To use the parameters, call
// Get. To apply new values to the parameters, call Set.
type ClientParameters struct {
	getValueLogger func(error)
	snapshot       atomic.Value
}

// NewClientParameters initializes a new ClientParameters with the default
// parameter values.
//
// getValueLogger is optional, and is used to report runtime errors with
// getValue; see comment in getValue.
func NewClientParameters(
	getValueLogger func(error)) (*ClientParameters, error) {

	clientParameters := &ClientParameters{
		getValueLogger: getValueLogger,
	}

	_, err := clientParameters.Set("", false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return clientParameters, nil
}

func makeDefaultParameters() (map[string]interface{}, error) {

	parameters := make(map[string]interface{})

	for name, defaults := range defaultClientParameters {

		if defaults.value == nil {
			return nil, errors.Tracef("default parameter missing value: %s", name)
		}

		if defaults.minimum != nil &&
			reflect.TypeOf(defaults.value) != reflect.TypeOf(defaults.minimum) {

			return nil, errors.Tracef("default parameter value and minimum type mismatch: %s", name)
		}

		_, isDuration := defaults.value.(time.Duration)
		if defaults.flags&useNetworkLatencyMultiplier != 0 && !isDuration {
			return nil, errors.Tracef("default non-duration parameter uses multipler: %s", name)
		}

		parameters[name] = defaults.value
	}

	return parameters, nil
}

// Set replaces the current parameters. First, a set of parameters are
// initialized using the default values. Then, each applyParameters is applied
// in turn, with the later instances having precedence.
//
// When skipOnError is true, unknown or invalid parameters in any
// applyParameters are skipped instead of aborting with an error.
//
// For protocol.TunnelProtocols and protocol.TLSProfiles type values, when
// skipOnError is true the values are filtered instead of validated, so
// only known tunnel protocols and TLS profiles are retained.
//
// When an error is returned, the previous parameters remain completely
// unmodified.
//
// For use in logging, Set returns a count of the number of parameters applied
// from each applyParameters.
func (p *ClientParameters) Set(
	tag string, skipOnError bool, applyParameters ...map[string]interface{}) ([]int, error) {

	var counts []int

	parameters, err := makeDefaultParameters()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Special case: TLSProfiles/LabeledTLSProfiles may reference CustomTLSProfiles names.
	// Inspect the CustomTLSProfiles parameter and extract its names. Do not
	// call Get().CustomTLSProfilesNames() as CustomTLSProfiles may not yet be
	// validated.

	var customTLSProfileNames []string

	customTLSProfilesValue := parameters[CustomTLSProfiles]
	for i := len(applyParameters) - 1; i >= 0; i-- {
		if v := applyParameters[i][CustomTLSProfiles]; v != nil {
			customTLSProfilesValue = v
			break
		}
	}
	if customTLSProfiles, ok := customTLSProfilesValue.(protocol.CustomTLSProfiles); ok {
		customTLSProfileNames = make([]string, len(customTLSProfiles))
		for i := 0; i < len(customTLSProfiles); i++ {
			customTLSProfileNames[i] = customTLSProfiles[i].Name
		}
	}

	for i := 0; i < len(applyParameters); i++ {

		count := 0

		for name, value := range applyParameters[i] {

			existingValue, ok := parameters[name]
			if !ok {
				if skipOnError {
					continue
				}
				return nil, errors.Tracef("unknown parameter: %s", name)
			}

			// Accept strings such as "1h" for duration parameters.

			switch existingValue.(type) {
			case time.Duration:
				if s, ok := value.(string); ok {
					if d, err := time.ParseDuration(s); err == nil {
						value = d
					}
				}
			}

			// A JSON remarshal resolves cases where applyParameters is a
			// result of unmarshal-into-interface, in which case non-scalar
			// values will not have the expected types; see:
			// https://golang.org/pkg/encoding/json/#Unmarshal. This remarshal
			// also results in a deep copy.

			marshaledValue, err := json.Marshal(value)
			if err != nil {
				continue
			}

			newValuePtr := reflect.New(reflect.TypeOf(existingValue))

			err = json.Unmarshal(marshaledValue, newValuePtr.Interface())
			if err != nil {
				if skipOnError {
					continue
				}
				return nil, errors.Tracef("unmarshal parameter %s failed: %s", name, err)
			}

			newValue := newValuePtr.Elem().Interface()

			// Perform type-specific validation for some cases.

			// TODO: require RemoteServerListSignaturePublicKey when
			// RemoteServerListURLs is set?

			switch v := newValue.(type) {
			case DownloadURLs:
				err := v.DecodeAndValidate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case protocol.TunnelProtocols:
				if skipOnError {
					newValue = v.PruneInvalid()
				} else {
					err := v.Validate()
					if err != nil {
						return nil, errors.Trace(err)
					}
				}
			case protocol.TLSProfiles:
				if skipOnError {
					newValue = v.PruneInvalid(customTLSProfileNames)
				} else {
					err := v.Validate(customTLSProfileNames)
					if err != nil {
						return nil, errors.Trace(err)
					}
				}
			case protocol.LabeledTLSProfiles:

				if skipOnError {
					newValue = v.PruneInvalid(customTLSProfileNames)
				} else {
					err := v.Validate(customTLSProfileNames)
					if err != nil {
						return nil, errors.Trace(err)
					}
				}
			case protocol.QUICVersions:
				if skipOnError {
					newValue = v.PruneInvalid()
				} else {
					err := v.Validate()
					if err != nil {
						return nil, errors.Trace(err)
					}
				}
			case protocol.LabeledQUICVersions:
				if skipOnError {
					newValue = v.PruneInvalid()
				} else {
					err := v.Validate()
					if err != nil {
						return nil, errors.Trace(err)
					}
				}
			case protocol.CustomTLSProfiles:
				err := v.Validate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case KeyValues:
				err := v.Validate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case *BPFProgramSpec:
				if v != nil {
					err := v.Validate()
					if err != nil {
						if skipOnError {
							continue
						}
						return nil, errors.Trace(err)
					}
				}
			}

			// Enforce any minimums. Assumes defaultClientParameters[name]
			// exists.
			if defaultClientParameters[name].minimum != nil {
				valid := true
				switch v := newValue.(type) {
				case int:
					m, ok := defaultClientParameters[name].minimum.(int)
					if !ok || v < m {
						valid = false
					}
				case float64:
					m, ok := defaultClientParameters[name].minimum.(float64)
					if !ok || v < m {
						valid = false
					}
				case time.Duration:
					m, ok := defaultClientParameters[name].minimum.(time.Duration)
					if !ok || v < m {
						valid = false
					}
				default:
					if skipOnError {
						continue
					}
					return nil, errors.Tracef("unexpected parameter with minimum: %s", name)
				}
				if !valid {
					if skipOnError {
						continue
					}
					return nil, errors.Tracef("parameter below minimum: %s", name)
				}
			}

			parameters[name] = newValue

			count++
		}

		counts = append(counts, count)
	}

	snapshot := &clientParametersSnapshot{
		getValueLogger: p.getValueLogger,
		tag:            tag,
		parameters:     parameters,
	}

	p.snapshot.Store(snapshot)

	return counts, nil
}

// Get returns the current parameters.
//
// Values read from the current parameters are not deep copies and must be
// treated read-only.
//
// The returned ClientParametersAccessor may be used to read multiple related
// values atomically and consistently while the current set of values in
// ClientParameters may change concurrently.
//
// Get does not perform any heap allocations and is intended for repeated,
// direct, low-overhead invocations.
func (p *ClientParameters) Get() ClientParametersAccessor {
	return ClientParametersAccessor{
		snapshot: p.snapshot.Load().(*clientParametersSnapshot)}
}

// GetCustom returns the current parameters while also setting customizations
// for this instance.
//
// The properties of Get also apply to GetCustom: must be read-only; atomic
// and consisent view; no heap allocations.
//
// Customizations include:
//
// - customNetworkLatencyMultiplier, which overrides NetworkLatencyMultiplier
//   for this instance only.
//
func (p *ClientParameters) GetCustom(
	customNetworkLatencyMultiplier float64) ClientParametersAccessor {

	return ClientParametersAccessor{
		snapshot:                       p.snapshot.Load().(*clientParametersSnapshot),
		customNetworkLatencyMultiplier: customNetworkLatencyMultiplier,
	}
}

// clientParametersSnapshot is an atomic snapshot of the client parameter
// values. ClientParameters.Get will return a snapshot which may be used to
// read multiple related values atomically and consistently while the current
// snapshot in ClientParameters may change concurrently.
type clientParametersSnapshot struct {
	getValueLogger func(error)
	tag            string
	parameters     map[string]interface{}
}

// getValue sets target to the value of the named parameter.
//
// It is an error if the name is not found, target is not a pointer, or the
// type of target points to does not match the value.
//
// Any of these conditions would be a bug in the caller. getValue does not
// panic in these cases as the client is deployed as a library in various apps
// and the failure of Psiphon may not be a failure for the app process.
//
// Instead, errors are logged to the getValueLogger and getValue leaves the
// target unset, which will result in the caller getting and using a zero
// value of the requested type.
func (p *clientParametersSnapshot) getValue(name string, target interface{}) {

	value, ok := p.parameters[name]
	if !ok {
		if p.getValueLogger != nil {
			p.getValueLogger(errors.Tracef(
				"value %s not found", name))
		}
		return
	}

	valueType := reflect.TypeOf(value)

	if reflect.PtrTo(valueType) != reflect.TypeOf(target) {
		if p.getValueLogger != nil {
			p.getValueLogger(errors.Tracef(
				"value %s has unexpected type %s", name, valueType.Name()))
		}
		return
	}

	// Note: there is no deep copy of parameter values; the returned value may
	// share memory with the original and should not be modified.

	targetValue := reflect.ValueOf(target)

	if targetValue.Kind() != reflect.Ptr {
		p.getValueLogger(errors.Tracef(
			"target for value %s is not pointer", name))
		return
	}

	targetValue.Elem().Set(reflect.ValueOf(value))
}

// ClientParametersAccessor provides consistent, atomic access to client
// parameter values. Any customizations are applied transparently.
type ClientParametersAccessor struct {
	snapshot                       *clientParametersSnapshot
	customNetworkLatencyMultiplier float64
}

// Close clears internal references to large memory objects, allowing them to
// be garbage collected. Call Close when done using a
// ClientParametersAccessor, where memory footprint is a concern, and where
// the ClientParametersAccessor is not immediately going out of scope. After
// Close is called, all other ClientParametersAccessor functions will panic if
// called.
func (p ClientParametersAccessor) Close() {
	p.snapshot = nil
}

// Tag returns the tag associated with these parameters.
func (p ClientParametersAccessor) Tag() string {
	return p.snapshot.tag
}

// String returns a string parameter value.
func (p ClientParametersAccessor) String(name string) string {
	value := ""
	p.snapshot.getValue(name, &value)
	return value
}

func (p ClientParametersAccessor) Strings(name string) []string {
	value := []string{}
	p.snapshot.getValue(name, &value)
	return value
}

// Int returns an int parameter value.
func (p ClientParametersAccessor) Int(name string) int {
	value := int(0)
	p.snapshot.getValue(name, &value)
	return value
}

// Bool returns a bool parameter value.
func (p ClientParametersAccessor) Bool(name string) bool {
	value := false
	p.snapshot.getValue(name, &value)
	return value
}

// Float returns a float64 parameter value.
func (p ClientParametersAccessor) Float(name string) float64 {
	value := float64(0.0)
	p.snapshot.getValue(name, &value)
	return value
}

// WeightedCoinFlip returns the result of prng.FlipWeightedCoin using the
// specified float parameter as the probability input.
func (p ClientParametersAccessor) WeightedCoinFlip(name string) bool {
	var value float64
	p.snapshot.getValue(name, &value)
	return prng.FlipWeightedCoin(value)
}

// Duration returns a time.Duration parameter value. When the duration
// parameter has the useNetworkLatencyMultiplier flag, the
// NetworkLatencyMultiplier is applied to the returned value.
func (p ClientParametersAccessor) Duration(name string) time.Duration {
	value := time.Duration(0)
	p.snapshot.getValue(name, &value)

	defaultParameter, ok := defaultClientParameters[name]
	if value > 0 && ok && defaultParameter.flags&useNetworkLatencyMultiplier != 0 {

		multiplier := float64(0.0)

		if p.customNetworkLatencyMultiplier != 0.0 {
			multiplier = p.customNetworkLatencyMultiplier
		} else {
			p.snapshot.getValue(NetworkLatencyMultiplier, &multiplier)
		}

		if multiplier > 0.0 {
			value = time.Duration(float64(value) * multiplier)
		}

	}

	return value
}

// TunnelProtocols returns a protocol.TunnelProtocols parameter value.
// If there is a corresponding Probability value, a weighted coin flip
// will be performed and, depending on the result, the value or the
// parameter default will be returned.
func (p ClientParametersAccessor) TunnelProtocols(name string) protocol.TunnelProtocols {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultClientParameters[name]
			if ok {
				defaultValue, ok := defaultParameter.value.(protocol.TunnelProtocols)
				if ok {
					value := make(protocol.TunnelProtocols, len(defaultValue))
					copy(value, defaultValue)
					return value
				}
			}
		}
	}

	value := protocol.TunnelProtocols{}
	p.snapshot.getValue(name, &value)
	return value
}

// TLSProfiles returns a protocol.TLSProfiles parameter value.
// If there is a corresponding Probability value, a weighted coin flip
// will be performed and, depending on the result, the value or the
// parameter default will be returned.
func (p ClientParametersAccessor) TLSProfiles(name string) protocol.TLSProfiles {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultClientParameters[name]
			if ok {
				defaultValue, ok := defaultParameter.value.(protocol.TLSProfiles)
				if ok {
					value := make(protocol.TLSProfiles, len(defaultValue))
					copy(value, defaultValue)
					return value
				}
			}
		}
	}

	value := protocol.TLSProfiles{}
	p.snapshot.getValue(name, &value)
	return value
}

// LabeledTLSProfiles returns a protocol.TLSProfiles parameter value
// corresponding to the specified labeled set and label value. The return
// value is nil when no set is found.
func (p ClientParametersAccessor) LabeledTLSProfiles(name, label string) protocol.TLSProfiles {
	var value protocol.LabeledTLSProfiles
	p.snapshot.getValue(name, &value)
	return value[label]
}

// QUICVersions returns a protocol.QUICVersions parameter value.
// If there is a corresponding Probability value, a weighted coin flip
// will be performed and, depending on the result, the value or the
// parameter default will be returned.
func (p ClientParametersAccessor) QUICVersions(name string) protocol.QUICVersions {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultClientParameters[name]
			if ok {
				defaultValue, ok := defaultParameter.value.(protocol.QUICVersions)
				if ok {
					value := make(protocol.QUICVersions, len(defaultValue))
					copy(value, defaultValue)
					return value
				}
			}
		}
	}

	value := protocol.QUICVersions{}
	p.snapshot.getValue(name, &value)
	return value
}

// LabeledQUICVersions returns a protocol.QUICVersions parameter value
// corresponding to the specified labeled set and label value. The return
// value is nil when no set is found.
func (p ClientParametersAccessor) LabeledQUICVersions(name, label string) protocol.QUICVersions {
	var value protocol.LabeledQUICVersions
	p.snapshot.getValue(name, &value)
	return value[label]
}

// DownloadURLs returns a DownloadURLs parameter value.
func (p ClientParametersAccessor) DownloadURLs(name string) DownloadURLs {
	value := DownloadURLs{}
	p.snapshot.getValue(name, &value)
	return value
}

// RateLimits returns a common.RateLimits parameter value.
func (p ClientParametersAccessor) RateLimits(name string) common.RateLimits {
	value := common.RateLimits{}
	p.snapshot.getValue(name, &value)
	return value
}

// HTTPHeaders returns an http.Header parameter value.
func (p ClientParametersAccessor) HTTPHeaders(name string) http.Header {
	value := make(http.Header)
	p.snapshot.getValue(name, &value)
	return value
}

// CustomTLSProfileNames returns the CustomTLSProfile.Name fields for
// each profile in the CustomTLSProfiles parameter value.
func (p ClientParametersAccessor) CustomTLSProfileNames() []string {
	value := protocol.CustomTLSProfiles{}
	p.snapshot.getValue(CustomTLSProfiles, &value)
	names := make([]string, len(value))
	for i := 0; i < len(value); i++ {
		names[i] = value[i].Name
	}
	return names
}

// CustomTLSProfile returns the CustomTLSProfile fields with the specified
// Name field if it exists in the CustomTLSProfiles parameter value.
// Returns nil if not found.
func (p ClientParametersAccessor) CustomTLSProfile(name string) *protocol.CustomTLSProfile {
	value := protocol.CustomTLSProfiles{}
	p.snapshot.getValue(CustomTLSProfiles, &value)

	// Note: linear lookup -- assumes a short list

	for i := 0; i < len(value); i++ {
		if value[i].Name == name {
			return value[i]
		}
	}
	return nil
}

// KeyValues returns a KeyValues parameter value.
func (p ClientParametersAccessor) KeyValues(name string) KeyValues {
	value := KeyValues{}
	p.snapshot.getValue(name, &value)
	return value
}

// BPFProgram returns an assembled BPF program corresponding to a
// BPFProgramSpec parameter value. Returns nil in the case of any empty
// program.
func (p ClientParametersAccessor) BPFProgram(name string) (bool, string, []bpf.RawInstruction) {
	var value *BPFProgramSpec
	p.snapshot.getValue(name, &value)
	if value == nil {
		return false, "", nil
	}
	// Validation checks that Assemble is successful.
	rawInstructions, _ := value.Assemble()
	return true, value.Name, rawInstructions
}

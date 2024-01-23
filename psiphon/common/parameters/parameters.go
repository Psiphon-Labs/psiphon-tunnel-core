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
determine Psiphon client and server behaviors.

Parameters include network timeouts, probabilities for actions, lists of
protocols, etc. Parameters are initialized with reasonable defaults. New
values may be applied, allowing the client or server to customize its
parameters from both a config file and tactics data. Sane minimum values are
enforced.

Parameters may be read and updated concurrently. The read mechanism offers a
snapshot so that related parameters, such as two Ints representing a range; or
a more complex series of related parameters; may be read in an atomic and
consistent way. For example:

	p := params.Get()
	min := p.Int("Min")
	max := p.Int("Max")
	p = nil

For long-running operations, it is recommended to set any pointer to the
snapshot to nil to allow garbage collection of old snaphots in cases where the
parameters change.

In general, parameters should be read as close to the point of use as possible
to ensure that dynamic changes to the parameter values take effect.

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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
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
	TunnelPoolSize                                   = "TunnelPoolSize"
	TunnelConnectTimeout                             = "TunnelConnectTimeout"
	EstablishTunnelTimeout                           = "EstablishTunnelTimeout"
	EstablishTunnelWorkTime                          = "EstablishTunnelWorkTime"
	EstablishTunnelPausePeriod                       = "EstablishTunnelPausePeriod"
	EstablishTunnelPausePeriodJitter                 = "EstablishTunnelPausePeriodJitter"
	EstablishTunnelServerAffinityGracePeriod         = "EstablishTunnelServerAffinityGracePeriod"
	StaggerConnectionWorkersPeriod                   = "StaggerConnectionWorkersPeriod"
	StaggerConnectionWorkersJitter                   = "StaggerConnectionWorkersJitter"
	LimitIntensiveConnectionWorkers                  = "LimitIntensiveConnectionWorkers"
	UpstreamProxyErrorMinWaitDuration                = "UpstreamProxyErrorMinWaitDuration"
	UpstreamProxyErrorMaxWaitDuration                = "UpstreamProxyErrorMaxWaitDuration"
	IgnoreHandshakeStatsRegexps                      = "IgnoreHandshakeStatsRegexps"
	PrioritizeTunnelProtocolsProbability             = "PrioritizeTunnelProtocolsProbability"
	PrioritizeTunnelProtocols                        = "PrioritizeTunnelProtocols"
	PrioritizeTunnelProtocolsCandidateCount          = "PrioritizeTunnelProtocolsCandidateCount"
	InitialLimitTunnelProtocolsProbability           = "InitialLimitTunnelProtocolsProbability"
	InitialLimitTunnelProtocols                      = "InitialLimitTunnelProtocols"
	InitialLimitTunnelProtocolsCandidateCount        = "InitialLimitTunnelProtocolsCandidateCount"
	LimitTunnelProtocolsProbability                  = "LimitTunnelProtocolsProbability"
	LimitTunnelProtocols                             = "LimitTunnelProtocols"
	LimitTunnelDialPortNumbersProbability            = "LimitTunnelDialPortNumbersProbability"
	LimitTunnelDialPortNumbers                       = "LimitTunnelDialPortNumbers"
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
	QUICDisableClientPathMTUDiscoveryProbability     = "QUICDisableClientPathMTUDiscoveryProbability"
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
	SplitTunnelClassificationTTL                     = "SplitTunnelClassificationTTL"
	SplitTunnelClassificationMaxEntries              = "SplitTunnelClassificationMaxEntries"
	FetchUpgradeTimeout                              = "FetchUpgradeTimeout"
	FetchUpgradeRetryPeriod                          = "FetchUpgradeRetryPeriod"
	FetchUpgradeStalePeriod                          = "FetchUpgradeStalePeriod"
	UpgradeDownloadURLs                              = "UpgradeDownloadURLs"
	UpgradeDownloadClientVersionHeader               = "UpgradeDownloadClientVersionHeader"
	TotalBytesTransferredNoticePeriod                = "TotalBytesTransferredNoticePeriod"
	TotalBytesTransferredEmitMemoryMetrics           = "TotalBytesTransferredEmitMemoryMetrics"
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
	MeekAlternateCookieNameProbability               = "MeekAlternateCookieNameProbability"
	MeekAlternateContentTypeProbability              = "MeekAlternateContentTypeProbability"
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
	ReplayLaterRoundMoveToFrontProbability           = "ReplayLaterRoundMoveToFrontProbability"
	ReplayRetainFailedProbability                    = "ReplayRetainFailedProbability"
	ReplayIgnoreChangedConfigState                   = "ReplayIgnoreChangedConfigState"
	ReplayBPF                                        = "ReplayBPF"
	ReplaySSH                                        = "ReplaySSH"
	ReplayObfuscatorPadding                          = "ReplayObfuscatorPadding"
	ReplayFragmentor                                 = "ReplayFragmentor"
	ReplayTLSProfile                                 = "ReplayTLSProfile"
	ReplayFronting                                   = "ReplayFronting"
	ReplayHostname                                   = "ReplayHostname"
	ReplayQUICVersion                                = "ReplayQUICVersion"
	ReplayObfuscatedQUIC                             = "ReplayObfuscatedQUIC"
	ReplayObfuscatedQUICNonceTransformer             = "ReplayObfuscatedQUICNonceTransformer"
	ReplayConjureRegistration                        = "ReplayConjureRegistration"
	ReplayConjureTransport                           = "ReplayConjureTransport"
	ReplayLivenessTest                               = "ReplayLivenessTest"
	ReplayUserAgent                                  = "ReplayUserAgent"
	ReplayAPIRequestPadding                          = "ReplayAPIRequestPadding"
	ReplayHoldOffTunnel                              = "ReplayHoldOffTunnel"
	ReplayResolveParameters                          = "ReplayResolveParameters"
	ReplayHTTPTransformerParameters                  = "ReplayHTTPTransformerParameters"
	ReplayOSSHSeedTransformerParameters              = "ReplayOSSHSeedTransformerParameters"
	ReplayOSSHPrefix                                 = "ReplayOSSHPrefix"
	ReplayTLSFragmentClientHello                     = "ReplayTLSFragmentClientHello"
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
	ServerPacketManipulationSpecs                    = "ServerPacketManipulationSpecs"
	ServerProtocolPacketManipulations                = "ServerProtocolPacketManipulations"
	ServerPacketManipulationProbability              = "ServerPacketManipulationProbability"
	FeedbackUploadURLs                               = "FeedbackUploadURLs"
	FeedbackEncryptionPublicKey                      = "FeedbackEncryptionPublicKey"
	FeedbackTacticsWaitPeriod                        = "FeedbackTacticsWaitPeriod"
	FeedbackUploadMaxAttempts                        = "FeedbackUploadMaxAttempts"
	FeedbackUploadRetryMinDelaySeconds               = "FeedbackUploadRetryMinDelaySeconds"
	FeedbackUploadRetryMaxDelaySeconds               = "FeedbackUploadRetryMaxDelaySeconds"
	FeedbackUploadTimeoutSeconds                     = "FeedbackUploadTimeoutSeconds"
	ServerReplayPacketManipulation                   = "ServerReplayPacketManipulation"
	ServerReplayFragmentor                           = "ServerReplayFragmentor"
	ServerReplayUnknownGeoIP                         = "ServerReplayUnknownGeoIP"
	ServerReplayTTL                                  = "ServerReplayTTL"
	ServerReplayTargetWaitDuration                   = "ServerReplayTargetWaitDuration"
	ServerReplayTargetTunnelDuration                 = "ServerReplayTargetTunnelDuration"
	ServerReplayTargetUpstreamBytes                  = "ServerReplayTargetUpstreamBytes"
	ServerReplayTargetDownstreamBytes                = "ServerReplayTargetDownstreamBytes"
	ServerReplayFailedCountThreshold                 = "ServerReplayFailedCountThreshold"
	ServerBurstUpstreamDeadline                      = "ServerBurstUpstreamDeadline"
	ServerBurstUpstreamTargetBytes                   = "ServerBurstUpstreamTargetBytes"
	ServerBurstDownstreamDeadline                    = "ServerBurstDownstreamDeadline"
	ServerBurstDownstreamTargetBytes                 = "ServerBurstDownstreamTargetBytes"
	ClientBurstUpstreamDeadline                      = "ClientBurstUpstreamDeadline"
	ClientBurstUpstreamTargetBytes                   = "ClientBurstUpstreamTargetBytes"
	ClientBurstDownstreamDeadline                    = "ClientBurstDownstreamDeadline"
	ClientBurstDownstreamTargetBytes                 = "ClientBurstDownstreamTargetBytes"
	ConjureCachedRegistrationTTL                     = "ConjureCachedRegistrationTTL"
	ConjureAPIRegistrarURL                           = "ConjureAPIRegistrarURL"
	ConjureAPIRegistrarBidirectionalURL              = "ConjureAPIRegistrarBidirectionalURL"
	ConjureAPIRegistrarFrontingSpecs                 = "ConjureAPIRegistrarFrontingSpecs"
	ConjureAPIRegistrarMinDelay                      = "ConjureAPIRegistrarMinDelay"
	ConjureAPIRegistrarMaxDelay                      = "ConjureAPIRegistrarMaxDelay"
	ConjureDecoyRegistrarProbability                 = "ConjureDecoyRegistrarProbability"
	ConjureDecoyRegistrarWidth                       = "ConjureDecoyRegistrarWidth"
	ConjureDecoyRegistrarMinDelay                    = "ConjureDecoyRegistrarMinDelay"
	ConjureDecoyRegistrarMaxDelay                    = "ConjureDecoyRegistrarMaxDelay"
	ConjureEnableIPv6Dials                           = "ConjureEnableIPv6Dials"
	ConjureEnablePortRandomization                   = "ConjureEnablePortRandomization"
	ConjureEnableRegistrationOverrides               = "ConjureEnableRegistrationOverrides"
	ConjureLimitTransportsProbability                = "ConjureLimitTransportsProbability"
	ConjureLimitTransports                           = "ConjureLimitTransports"
	ConjureSTUNServerAddresses                       = "ConjureSTUNServerAddresses"
	ConjureDTLSEmptyInitialPacketProbability         = "ConjureDTLSEmptyInitialPacketProbability"
	CustomHostNameRegexes                            = "CustomHostNameRegexes"
	CustomHostNameProbability                        = "CustomHostNameProbability"
	CustomHostNameLimitProtocols                     = "CustomHostNameLimitProtocols"
	HoldOffTunnelMinDuration                         = "HoldOffTunnelMinDuration"
	HoldOffTunnelMaxDuration                         = "HoldOffTunnelMaxDuration"
	HoldOffTunnelProtocols                           = "HoldOffTunnelProtocols"
	HoldOffTunnelFrontingProviderIDs                 = "HoldOffTunnelFrontingProviderIDs"
	HoldOffTunnelProbability                         = "HoldOffTunnelProbability"
	RestrictFrontingProviderIDs                      = "RestrictFrontingProviderIDs"
	RestrictFrontingProviderIDsServerProbability     = "RestrictFrontingProviderIDsServerProbability"
	RestrictFrontingProviderIDsClientProbability     = "RestrictFrontingProviderIDsClientProbability"
	HoldOffDirectTunnelMinDuration                   = "HoldOffDirectTunnelMinDuration"
	HoldOffDirectTunnelMaxDuration                   = "HoldOffDirectTunnelMaxDuration"
	HoldOffDirectTunnelProviderRegions               = "HoldOffDirectTunnelProviderRegions"
	HoldOffDirectTunnelProbability                   = "HoldOffDirectTunnelProbability"
	RestrictDirectProviderRegions                    = "RestrictDirectProviderRegions"
	RestrictDirectProviderIDsServerProbability       = "RestrictDirectProviderIDsServerProbability"
	RestrictDirectProviderIDsClientProbability       = "RestrictDirectProviderIDsClientProbability"
	UpstreamProxyAllowAllServerEntrySources          = "UpstreamProxyAllowAllServerEntrySources"
	DestinationBytesMetricsASN                       = "DestinationBytesMetricsASN"
	DNSResolverAttemptsPerServer                     = "DNSResolverAttemptsPerServer"
	DNSResolverAttemptsPerPreferredServer            = "DNSResolverAttemptsPerPreferredServer"
	DNSResolverRequestTimeout                        = "DNSResolverRequestTimeout"
	DNSResolverAwaitTimeout                          = "DNSResolverAwaitTimeout"
	DNSResolverPreresolvedIPAddressCIDRs             = "DNSResolverPreresolvedIPAddressCIDRs"
	DNSResolverPreresolvedIPAddressProbability       = "DNSResolverPreresolvedIPAddressProbability"
	DNSResolverAlternateServers                      = "DNSResolverAlternateServers"
	DNSResolverPreferredAlternateServers             = "DNSResolverPreferredAlternateServers"
	DNSResolverPreferAlternateServerProbability      = "DNSResolverPreferAlternateServerProbability"
	DNSResolverProtocolTransformSpecs                = "DNSResolverProtocolTransformSpecs"
	DNSResolverProtocolTransformScopedSpecNames      = "DNSResolverProtocolTransformScopedSpecNames"
	DNSResolverProtocolTransformProbability          = "DNSResolverProtocolTransformProbability"
	DNSResolverIncludeEDNS0Probability               = "DNSResolverIncludeEDNS0Probability"
	DNSResolverCacheExtensionInitialTTL              = "DNSResolverCacheExtensionInitialTTL"
	DNSResolverCacheExtensionVerifiedTTL             = "DNSResolverCacheExtensionVerifiedTTL"
	AddFrontingProviderPsiphonFrontingHeader         = "AddFrontingProviderPsiphonFrontingHeader"
	DirectHTTPProtocolTransformSpecs                 = "DirectHTTPProtocolTransformSpecs"
	DirectHTTPProtocolTransformScopedSpecNames       = "DirectHTTPProtocolTransformScopedSpecNames"
	DirectHTTPProtocolTransformProbability           = "DirectHTTPProtocolTransformProbability"
	FrontedHTTPProtocolTransformSpecs                = "FrontedHTTPProtocolTransformSpecs"
	FrontedHTTPProtocolTransformScopedSpecNames      = "FrontedHTTPProtocolTransformScopedSpecNames"
	FrontedHTTPProtocolTransformProbability          = "FrontedHTTPProtocolTransformProbability"
	OSSHObfuscatorSeedTransformSpecs                 = "OSSHObfuscatorSeedTransformSpecs"
	OSSHObfuscatorSeedTransformScopedSpecNames       = "OSSHObfuscatorSeedTransformScopedSpecNames"
	OSSHObfuscatorSeedTransformProbability           = "OSSHObfuscatorSeedTransformProbability"
	ObfuscatedQUICNonceTransformSpecs                = "ObfuscatedQUICNonceTransformSpecs"
	ObfuscatedQUICNonceTransformScopedSpecNames      = "ObfuscatedQUICNonceTransformScopedSpecNames"
	ObfuscatedQUICNonceTransformProbability          = "ObfuscatedQUICNonceTransformProbability"
	OSSHPrefixSpecs                                  = "OSSHPrefixSpecs"
	OSSHPrefixScopedSpecNames                        = "OSSHPrefixScopedSpecNames"
	OSSHPrefixProbability                            = "OSSHPrefixProbability"
	OSSHPrefixSplitMinDelay                          = "OSSHPrefixSplitMinDelay"
	OSSHPrefixSplitMaxDelay                          = "OSSHPrefixSplitMaxDelay"
	OSSHPrefixEnableFragmentor                       = "OSSHPrefixEnableFragmentor"
	ServerOSSHPrefixSpecs                            = "ServerOSSHPrefixSpecs"
	TLSTunnelTrafficShapingProbability               = "TLSTunnelTrafficShapingProbability"
	TLSTunnelMinTLSPadding                           = "TLSTunnelMinTLSPadding"
	TLSTunnelMaxTLSPadding                           = "TLSTunnelMaxTLSPadding"
	TLSFragmentClientHelloProbability                = "TLSFragmentClientHelloProbability"
	TLSFragmentClientHelloLimitProtocols             = "TLSFragmentClientHelloLimitProtocols"

	// Retired parameters

	ReplayRandomizedTLSProfile = "ReplayRandomizedTLSProfile"
)

const (
	useNetworkLatencyMultiplier = 1
	serverSideOnly              = 2
)

// defaultParameters specifies the type, default value, and minimum value for
// all dynamically configurable client and server parameters.
//
// Do not change the names or types of existing values, as that can break
// client logic or cause parameters to not be applied.
//
// Minimum values are a fail-safe for cases where lower values would break the
// client logic. For example, setting a ConnectionWorkerPoolSize of 0 would
// make the client never connect.
var defaultParameters = map[string]struct {
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
	TunnelPoolSize:                           {value: 1, minimum: 1},
	TunnelConnectTimeout:                     {value: 20 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	EstablishTunnelTimeout:                   {value: 300 * time.Second, minimum: time.Duration(0)},
	EstablishTunnelWorkTime:                  {value: 60 * time.Second, minimum: 1 * time.Second},
	EstablishTunnelPausePeriod:               {value: 5 * time.Second, minimum: 1 * time.Millisecond},
	EstablishTunnelPausePeriodJitter:         {value: 0.1, minimum: 0.0},
	EstablishTunnelServerAffinityGracePeriod: {value: 1 * time.Second, minimum: time.Duration(0), flags: useNetworkLatencyMultiplier},
	StaggerConnectionWorkersPeriod:           {value: time.Duration(0), minimum: time.Duration(0)},
	StaggerConnectionWorkersJitter:           {value: 0.1, minimum: 0.0},
	LimitIntensiveConnectionWorkers:          {value: 0, minimum: 0},
	UpstreamProxyErrorMinWaitDuration:        {value: 10 * time.Second, minimum: time.Duration(0)},
	UpstreamProxyErrorMaxWaitDuration:        {value: 30 * time.Second, minimum: time.Duration(0)},
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

	LimitTunnelDialPortNumbersProbability: {value: 1.0, minimum: 0.0},
	LimitTunnelDialPortNumbers:            {value: TunnelProtocolPortLists{}},

	LimitTLSProfilesProbability:           {value: 1.0, minimum: 0.0},
	LimitTLSProfiles:                      {value: protocol.TLSProfiles{}},
	UseOnlyCustomTLSProfiles:              {value: false},
	CustomTLSProfiles:                     {value: protocol.CustomTLSProfiles{}},
	SelectRandomizedTLSProfileProbability: {value: 0.25, minimum: 0.0},
	NoDefaultTLSSessionIDProbability:      {value: 0.5, minimum: 0.0},
	DisableFrontingProviderTLSProfiles:    {value: protocol.LabeledTLSProfiles{}},

	LimitQUICVersionsProbability:                 {value: 1.0, minimum: 0.0},
	LimitQUICVersions:                            {value: protocol.QUICVersions{}},
	DisableFrontingProviderQUICVersions:          {value: protocol.LabeledQUICVersions{}},
	QUICDisableClientPathMTUDiscoveryProbability: {value: 0.0, minimum: 0.0},

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
	SpeedTestMaxSampleCount:  {value: 5, minimum: 1},

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
	RemoteServerListURLs:               {value: TransferURLs{}},
	ObfuscatedServerListRootURLs:       {value: TransferURLs{}},

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

	// FetchSplitTunnelRoutesTimeout, SplitTunnelRoutesURLFormat,
	// SplitTunnelRoutesSignaturePublicKey and SplitTunnelDNSServer are obsoleted
	// by the server-assisted split tunnel implementation.
	// TODO: remove once no longer required for older clients.
	FetchSplitTunnelRoutesTimeout:       {value: 60 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	SplitTunnelRoutesURLFormat:          {value: ""},
	SplitTunnelRoutesSignaturePublicKey: {value: ""},
	SplitTunnelDNSServer:                {value: ""},

	SplitTunnelClassificationTTL:        {value: 24 * time.Hour, minimum: 0 * time.Second},
	SplitTunnelClassificationMaxEntries: {value: 65536, minimum: 0},

	FetchUpgradeTimeout:                {value: 60 * time.Second, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	FetchUpgradeRetryPeriod:            {value: 30 * time.Second, minimum: 1 * time.Millisecond},
	FetchUpgradeStalePeriod:            {value: 6 * time.Hour, minimum: 1 * time.Hour},
	UpgradeDownloadURLs:                {value: TransferURLs{}},
	UpgradeDownloadClientVersionHeader: {value: ""},

	TotalBytesTransferredNoticePeriod:      {value: 5 * time.Minute, minimum: 1 * time.Second},
	TotalBytesTransferredEmitMemoryMetrics: {value: true},

	// The meek server times out inactive sessions after 45 seconds, so this
	// is a soft max for MeekMaxPollInterval,  MeekRoundTripTimeout, and
	// MeekRoundTripRetryDeadline.
	//
	// MeekCookieMaxPadding cannot exceed common.OBFUSCATE_SEED_LENGTH.
	//
	// MeekMinTLSPadding/MeekMaxTLSPadding are subject to TLS server limitations.
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
	MeekTrafficShapingProbability:              {value: 1.0, minimum: 0.0},
	MeekTrafficShapingLimitProtocols:           {value: protocol.TunnelProtocols{}},
	MeekMinTLSPadding:                          {value: 0, minimum: 0},
	MeekMaxTLSPadding:                          {value: 0, minimum: 0},
	MeekMinLimitRequestPayloadLength:           {value: 65536, minimum: 1},
	MeekMaxLimitRequestPayloadLength:           {value: 65536, minimum: 1},
	MeekRedialTLSProbability:                   {value: 0.0, minimum: 0.0},
	MeekAlternateCookieNameProbability:         {value: 0.5, minimum: 0.0},
	MeekAlternateContentTypeProbability:        {value: 0.5, minimum: 0.0},

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
	ReplayLaterRoundMoveToFrontProbability: {value: 0.0, minimum: 0.0},
	ReplayRetainFailedProbability:          {value: 0.5, minimum: 0.0},
	ReplayIgnoreChangedConfigState:         {value: false},
	ReplayBPF:                              {value: true},
	ReplaySSH:                              {value: true},
	ReplayObfuscatorPadding:                {value: true},
	ReplayFragmentor:                       {value: true},
	ReplayTLSProfile:                       {value: true},
	ReplayFronting:                         {value: true},
	ReplayHostname:                         {value: true},
	ReplayQUICVersion:                      {value: true},
	ReplayObfuscatedQUIC:                   {value: true},
	ReplayObfuscatedQUICNonceTransformer:   {value: true},
	ReplayConjureRegistration:              {value: true},
	ReplayConjureTransport:                 {value: true},
	ReplayLivenessTest:                     {value: true},
	ReplayUserAgent:                        {value: true},
	ReplayAPIRequestPadding:                {value: true},
	ReplayHoldOffTunnel:                    {value: true},
	ReplayResolveParameters:                {value: true},
	ReplayHTTPTransformerParameters:        {value: true},
	ReplayOSSHSeedTransformerParameters:    {value: true},
	ReplayOSSHPrefix:                       {value: true},
	ReplayTLSFragmentClientHello:           {value: true},

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

	BPFServerTCPProgram:     {value: (*BPFProgramSpec)(nil), flags: serverSideOnly},
	BPFServerTCPProbability: {value: 0.5, minimum: 0.0, flags: serverSideOnly},
	BPFClientTCPProgram:     {value: (*BPFProgramSpec)(nil)},
	BPFClientTCPProbability: {value: 0.5, minimum: 0.0},

	ServerPacketManipulationSpecs:       {value: PacketManipulationSpecs{}, flags: serverSideOnly},
	ServerProtocolPacketManipulations:   {value: make(ProtocolPacketManipulations), flags: serverSideOnly},
	ServerPacketManipulationProbability: {value: 0.5, minimum: 0.0, flags: serverSideOnly},

	FeedbackUploadURLs:          {value: TransferURLs{}},
	FeedbackEncryptionPublicKey: {value: ""},
	FeedbackTacticsWaitPeriod:   {value: 5 * time.Second, minimum: 0 * time.Second, flags: useNetworkLatencyMultiplier},
	FeedbackUploadMaxAttempts:   {value: 5, minimum: 0},
	// TODO: rename -- remove "Seconds" suffix
	FeedbackUploadRetryMinDelaySeconds: {value: 1 * time.Minute, minimum: time.Duration(0), flags: useNetworkLatencyMultiplier},
	FeedbackUploadRetryMaxDelaySeconds: {value: 5 * time.Minute, minimum: 1 * time.Second, flags: useNetworkLatencyMultiplier},
	FeedbackUploadTimeoutSeconds:       {value: 30 * time.Second, minimum: 0 * time.Second, flags: useNetworkLatencyMultiplier},

	ServerReplayPacketManipulation:    {value: true, flags: serverSideOnly},
	ServerReplayFragmentor:            {value: true, flags: serverSideOnly},
	ServerReplayUnknownGeoIP:          {value: false, flags: serverSideOnly},
	ServerReplayTTL:                   {value: time.Duration(0), minimum: time.Duration(0), flags: serverSideOnly},
	ServerReplayTargetWaitDuration:    {value: time.Duration(0), minimum: time.Duration(0), flags: serverSideOnly},
	ServerReplayTargetTunnelDuration:  {value: time.Duration(0), minimum: time.Duration(0), flags: serverSideOnly},
	ServerReplayTargetUpstreamBytes:   {value: 0, minimum: 0, flags: serverSideOnly},
	ServerReplayTargetDownstreamBytes: {value: 0, minimum: 0, flags: serverSideOnly},
	ServerReplayFailedCountThreshold:  {value: 0, minimum: 0, flags: serverSideOnly},

	ServerBurstUpstreamTargetBytes:   {value: 0, minimum: 0, flags: serverSideOnly},
	ServerBurstUpstreamDeadline:      {value: time.Duration(0), minimum: time.Duration(0), flags: serverSideOnly},
	ServerBurstDownstreamTargetBytes: {value: 0, minimum: 0, flags: serverSideOnly},
	ServerBurstDownstreamDeadline:    {value: time.Duration(0), minimum: time.Duration(0), flags: serverSideOnly},
	ClientBurstUpstreamTargetBytes:   {value: 0, minimum: 0},
	ClientBurstUpstreamDeadline:      {value: time.Duration(0), minimum: time.Duration(0)},
	ClientBurstDownstreamTargetBytes: {value: 0, minimum: 0},
	ClientBurstDownstreamDeadline:    {value: time.Duration(0), minimum: time.Duration(0)},

	ConjureCachedRegistrationTTL: {value: time.Duration(0), minimum: time.Duration(0)},
	// ConjureAPIRegistrarURL parameter is obsoleted by ConjureAPIRegistrarBidirectionalURL.
	// TODO: remove once no longer required for older clients.
	ConjureAPIRegistrarURL:                   {value: ""},
	ConjureAPIRegistrarBidirectionalURL:      {value: ""},
	ConjureAPIRegistrarFrontingSpecs:         {value: FrontingSpecs{}},
	ConjureAPIRegistrarMinDelay:              {value: time.Duration(0), minimum: time.Duration(0)},
	ConjureAPIRegistrarMaxDelay:              {value: time.Duration(0), minimum: time.Duration(0)},
	ConjureDecoyRegistrarProbability:         {value: 0.0, minimum: 0.0},
	ConjureDecoyRegistrarWidth:               {value: 5, minimum: 0},
	ConjureDecoyRegistrarMinDelay:            {value: time.Duration(0), minimum: time.Duration(0)},
	ConjureDecoyRegistrarMaxDelay:            {value: time.Duration(0), minimum: time.Duration(0)},
	ConjureEnableIPv6Dials:                   {value: true},
	ConjureEnablePortRandomization:           {value: true},
	ConjureEnableRegistrationOverrides:       {value: false},
	ConjureLimitTransportsProbability:        {value: 1.0, minimum: 0.0},
	ConjureLimitTransports:                   {value: protocol.ConjureTransports{}},
	ConjureSTUNServerAddresses:               {value: []string{}},
	ConjureDTLSEmptyInitialPacketProbability: {value: 0.0, minimum: 0.0},

	CustomHostNameRegexes:        {value: RegexStrings{}},
	CustomHostNameProbability:    {value: 0.0, minimum: 0.0},
	CustomHostNameLimitProtocols: {value: protocol.TunnelProtocols{}},

	HoldOffTunnelMinDuration:         {value: time.Duration(0), minimum: time.Duration(0)},
	HoldOffTunnelMaxDuration:         {value: time.Duration(0), minimum: time.Duration(0)},
	HoldOffTunnelProtocols:           {value: protocol.TunnelProtocols{}},
	HoldOffTunnelFrontingProviderIDs: {value: []string{}},
	HoldOffTunnelProbability:         {value: 0.0, minimum: 0.0},

	RestrictFrontingProviderIDs:                  {value: []string{}},
	RestrictFrontingProviderIDsServerProbability: {value: 0.0, minimum: 0.0, flags: serverSideOnly},
	RestrictFrontingProviderIDsClientProbability: {value: 0.0, minimum: 0.0},

	HoldOffDirectTunnelMinDuration:     {value: time.Duration(0), minimum: time.Duration(0)},
	HoldOffDirectTunnelMaxDuration:     {value: time.Duration(0), minimum: time.Duration(0)},
	HoldOffDirectTunnelProviderRegions: {value: KeyStrings{}},
	HoldOffDirectTunnelProbability:     {value: 0.0, minimum: 0.0},

	RestrictDirectProviderRegions:              {value: KeyStrings{}},
	RestrictDirectProviderIDsServerProbability: {value: 0.0, minimum: 0.0, flags: serverSideOnly},
	RestrictDirectProviderIDsClientProbability: {value: 0.0, minimum: 0.0},

	UpstreamProxyAllowAllServerEntrySources: {value: false},

	DestinationBytesMetricsASN: {value: "", flags: serverSideOnly},

	DNSResolverAttemptsPerServer:                {value: 2, minimum: 1},
	DNSResolverAttemptsPerPreferredServer:       {value: 1, minimum: 1},
	DNSResolverRequestTimeout:                   {value: 5 * time.Second, minimum: 100 * time.Millisecond, flags: useNetworkLatencyMultiplier},
	DNSResolverAwaitTimeout:                     {value: 10 * time.Millisecond, minimum: 1 * time.Millisecond, flags: useNetworkLatencyMultiplier},
	DNSResolverPreresolvedIPAddressCIDRs:        {value: LabeledCIDRs{}},
	DNSResolverPreresolvedIPAddressProbability:  {value: 0.0, minimum: 0.0},
	DNSResolverAlternateServers:                 {value: []string{}},
	DNSResolverPreferredAlternateServers:        {value: []string{}},
	DNSResolverPreferAlternateServerProbability: {value: 0.0, minimum: 0.0},
	DNSResolverProtocolTransformSpecs:           {value: transforms.Specs{}},
	DNSResolverProtocolTransformScopedSpecNames: {value: transforms.ScopedSpecNames{}},
	DNSResolverProtocolTransformProbability:     {value: 0.0, minimum: 0.0},
	DNSResolverIncludeEDNS0Probability:          {value: 0.0, minimum: 0.0},
	DNSResolverCacheExtensionInitialTTL:         {value: time.Duration(0), minimum: time.Duration(0)},
	DNSResolverCacheExtensionVerifiedTTL:        {value: time.Duration(0), minimum: time.Duration(0)},

	AddFrontingProviderPsiphonFrontingHeader: {value: protocol.LabeledTunnelProtocols{}},

	DirectHTTPProtocolTransformSpecs:            {value: transforms.Specs{}},
	DirectHTTPProtocolTransformScopedSpecNames:  {value: transforms.ScopedSpecNames{}},
	DirectHTTPProtocolTransformProbability:      {value: 0.0, minimum: 0.0},
	FrontedHTTPProtocolTransformSpecs:           {value: transforms.Specs{}},
	FrontedHTTPProtocolTransformScopedSpecNames: {value: transforms.ScopedSpecNames{}},
	FrontedHTTPProtocolTransformProbability:     {value: 0.0, minimum: 0.0},

	OSSHObfuscatorSeedTransformSpecs:           {value: transforms.Specs{}},
	OSSHObfuscatorSeedTransformScopedSpecNames: {value: transforms.ScopedSpecNames{}},
	OSSHObfuscatorSeedTransformProbability:     {value: 0.0, minimum: 0.0},

	ObfuscatedQUICNonceTransformSpecs:           {value: transforms.Specs{}},
	ObfuscatedQUICNonceTransformScopedSpecNames: {value: transforms.ScopedSpecNames{}},
	ObfuscatedQUICNonceTransformProbability:     {value: 0.0, minimum: 0.0},

	OSSHPrefixSpecs:            {value: transforms.Specs{}},
	OSSHPrefixScopedSpecNames:  {value: transforms.ScopedSpecNames{}},
	OSSHPrefixProbability:      {value: 0.0, minimum: 0.0},
	OSSHPrefixSplitMinDelay:    {value: time.Duration(0), minimum: time.Duration(0)},
	OSSHPrefixSplitMaxDelay:    {value: time.Duration(0), minimum: time.Duration(0)},
	OSSHPrefixEnableFragmentor: {value: false},
	ServerOSSHPrefixSpecs:      {value: transforms.Specs{}, flags: serverSideOnly},

	// TLSTunnelMinTLSPadding/TLSTunnelMaxTLSPadding are subject to TLS server limitations.

	TLSTunnelTrafficShapingProbability: {value: 1.0, minimum: 0.0},
	TLSTunnelMinTLSPadding:             {value: 0, minimum: 0},
	TLSTunnelMaxTLSPadding:             {value: 0, minimum: 0},

	TLSFragmentClientHelloProbability:    {value: 0.0, minimum: 0.0},
	TLSFragmentClientHelloLimitProtocols: {value: protocol.TunnelProtocols{}},
}

// IsServerSideOnly indicates if the parameter specified by name is used
// server-side only.
func IsServerSideOnly(name string) bool {
	defaultParameter, ok := defaultParameters[name]
	return ok && (defaultParameter.flags&serverSideOnly) != 0
}

// Parameters is a set of parameters. To use the parameters, call Get. To
// apply new values to the parameters, call Set.
type Parameters struct {
	getValueLogger func(error)
	snapshot       atomic.Value
}

// NewParameters initializes a new Parameters with the default parameter
// values.
//
// getValueLogger is optional, and is used to report runtime errors with
// getValue; see comment in getValue.
func NewParameters(
	getValueLogger func(error)) (*Parameters, error) {

	parameters := &Parameters{
		getValueLogger: getValueLogger,
	}

	_, err := parameters.Set("", false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return parameters, nil
}

func makeDefaultParameters() (map[string]interface{}, error) {

	parameters := make(map[string]interface{})

	for name, defaults := range defaultParameters {

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
func (p *Parameters) Set(
	tag string, skipOnError bool, applyParameters ...map[string]interface{}) ([]int, error) {

	makeTypedValue := func(templateValue, value interface{}) (interface{}, error) {

		// Accept strings such as "1h" for duration parameters.

		switch templateValue.(type) {
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
			return nil, errors.Trace(err)
		}

		newValuePtr := reflect.New(reflect.TypeOf(templateValue))

		err = json.Unmarshal(marshaledValue, newValuePtr.Interface())
		if err != nil {
			return nil, errors.Trace(err)
		}

		return newValuePtr.Elem().Interface(), nil
	}

	getAppliedValue := func(
		name string,
		parameters map[string]interface{},
		applyParameters []map[string]interface{}) (interface{}, error) {

		templateValue := parameters[name]
		if templateValue == nil {
			return nil, errors.Tracef("unknown parameter: %s", name)
		}

		value := templateValue
		for i := len(applyParameters) - 1; i >= 0; i-- {
			if v := applyParameters[i][name]; v != nil {
				value = v
				break
			}
		}

		return makeTypedValue(templateValue, value)
	}

	var counts []int

	parameters, err := makeDefaultParameters()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Special case: TLSProfiles/LabeledTLSProfiles may reference
	// CustomTLSProfiles names. Inspect the CustomTLSProfiles parameter and
	// extract its names. Do not call Get().CustomTLSProfilesNames() as
	// CustomTLSProfiles may not yet be validated.

	customTLSProfilesValue, err := getAppliedValue(
		CustomTLSProfiles, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	customTLSProfiles, _ := customTLSProfilesValue.(protocol.CustomTLSProfiles)
	customTLSProfileNames := make([]string, len(customTLSProfiles))
	for i, profile := range customTLSProfiles {
		customTLSProfileNames[i] = profile.Name
	}

	// Special case: PacketManipulations will reference PacketManipulationSpecs.

	serverPacketManipulationSpecsValue, err := getAppliedValue(
		ServerPacketManipulationSpecs, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	serverPacketManipulationSpecs, _ :=
		serverPacketManipulationSpecsValue.(PacketManipulationSpecs)

	// Special case: ProtocolTransformScopedSpecNames will reference
	// ProtocolTransformSpecs.

	dnsResolverProtocolTransformSpecsValue, err := getAppliedValue(
		DNSResolverProtocolTransformSpecs, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	dnsResolverProtocolTransformSpecs, _ :=
		dnsResolverProtocolTransformSpecsValue.(transforms.Specs)

	directHttpProtocolTransformSpecsValue, err := getAppliedValue(
		DirectHTTPProtocolTransformSpecs, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	directHttpProtocolTransformSpecs, _ :=
		directHttpProtocolTransformSpecsValue.(transforms.Specs)

	frontedHttpProtocolTransformSpecsValue, err := getAppliedValue(
		FrontedHTTPProtocolTransformSpecs, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	frontedHttpProtocolTransformSpecs, _ :=
		frontedHttpProtocolTransformSpecsValue.(transforms.Specs)

	osshObfuscatorSeedTransformSpecsValue, err := getAppliedValue(
		OSSHObfuscatorSeedTransformSpecs, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	osshObfuscatorSeedTransformSpecs, _ :=
		osshObfuscatorSeedTransformSpecsValue.(transforms.Specs)

	obfuscatedQuicNonceTransformSpecsValue, err := getAppliedValue(
		ObfuscatedQUICNonceTransformSpecs, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	obfuscatedQuicNonceTransformSpecs, _ :=
		obfuscatedQuicNonceTransformSpecsValue.(transforms.Specs)

	osshPrefixSpecsValue, err := getAppliedValue(
		OSSHPrefixSpecs, parameters, applyParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	osshPrefixSpecs, _ := osshPrefixSpecsValue.(transforms.Specs)

	for i := 0; i < len(applyParameters); i++ {

		count := 0

		for name, value := range applyParameters[i] {

			templateValue, ok := parameters[name]
			if !ok {
				if skipOnError {
					continue
				}
				return nil, errors.Tracef("unknown parameter: %s", name)
			}

			newValue, err := makeTypedValue(templateValue, value)
			if err != nil {
				if skipOnError {
					continue
				}
				return nil, errors.Tracef(
					"unmarshal parameter %s failed: %v", name, err)
			}

			// Perform type-specific validation for some cases.

			// TODO: require RemoteServerListSignaturePublicKey when
			// RemoteServerListURLs is set?

			switch v := newValue.(type) {
			case TransferURLs:
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
			case protocol.LabeledTunnelProtocols:
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
			case KeyStrings:
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
			case PacketManipulationSpecs:
				err := v.Validate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case ProtocolPacketManipulations:

				var packetManipulationSpecs PacketManipulationSpecs
				if name == ServerProtocolPacketManipulations {
					packetManipulationSpecs = serverPacketManipulationSpecs
				}

				err := v.Validate(packetManipulationSpecs)
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case RegexStrings:
				err := v.Validate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case FrontingSpecs:
				err := v.Validate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case TunnelProtocolPortLists:
				err := v.Validate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case LabeledCIDRs:
				err := v.Validate()
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case transforms.Specs:
				prefixMode := false
				if name == OSSHPrefixSpecs || name == ServerOSSHPrefixSpecs {
					prefixMode = true
				}
				err := v.Validate(prefixMode)
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case transforms.ScopedSpecNames:

				var specs transforms.Specs
				if name == DNSResolverProtocolTransformScopedSpecNames {
					specs = dnsResolverProtocolTransformSpecs
				} else if name == DirectHTTPProtocolTransformScopedSpecNames {
					specs = directHttpProtocolTransformSpecs
				} else if name == FrontedHTTPProtocolTransformScopedSpecNames {
					specs = frontedHttpProtocolTransformSpecs
				} else if name == OSSHObfuscatorSeedTransformScopedSpecNames {
					specs = osshObfuscatorSeedTransformSpecs
				} else if name == ObfuscatedQUICNonceTransformScopedSpecNames {
					specs = obfuscatedQuicNonceTransformSpecs
				} else if name == OSSHPrefixScopedSpecNames {
					specs = osshPrefixSpecs
				}

				err := v.Validate(specs)
				if err != nil {
					if skipOnError {
						continue
					}
					return nil, errors.Trace(err)
				}
			case protocol.ConjureTransports:
				if skipOnError {
					newValue = v.PruneInvalid()
				} else {
					err := v.Validate()
					if err != nil {
						return nil, errors.Trace(err)
					}
				}
			}

			// Enforce any minimums. Assumes defaultParameters[name]
			// exists.
			if defaultParameters[name].minimum != nil {
				valid := true
				switch v := newValue.(type) {
				case int:
					m, ok := defaultParameters[name].minimum.(int)
					if !ok || v < m {
						valid = false
					}
				case float64:
					m, ok := defaultParameters[name].minimum.(float64)
					if !ok || v < m {
						valid = false
					}
				case time.Duration:
					m, ok := defaultParameters[name].minimum.(time.Duration)
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

	snapshot := &parametersSnapshot{
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
// The returned ParametersAccessor may be used to read multiple related values
// atomically and consistently while the current set of values in Parameters
// may change concurrently.
//
// Get does not perform any heap allocations and is intended for repeated,
// direct, low-overhead invocations.
func (p *Parameters) Get() ParametersAccessor {
	return ParametersAccessor{
		snapshot: p.snapshot.Load().(*parametersSnapshot)}
}

// GetCustom returns the current parameters while also setting customizations
// for this instance.
//
// The properties of Get also apply to GetCustom: must be read-only; atomic
// and consisent view; no heap allocations.
//
// Customizations include:
//
//   - customNetworkLatencyMultiplier, which overrides NetworkLatencyMultiplier
//     for this instance only.
func (p *Parameters) GetCustom(
	customNetworkLatencyMultiplier float64) ParametersAccessor {

	return ParametersAccessor{
		snapshot:                       p.snapshot.Load().(*parametersSnapshot),
		customNetworkLatencyMultiplier: customNetworkLatencyMultiplier,
	}
}

// parametersSnapshot is an atomic snapshot of the parameter values.
// Parameters.Get will return a snapshot which may be used to read multiple
// related values atomically and consistently while the current snapshot in
// Parameters may change concurrently.
type parametersSnapshot struct {
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
// panic in these cases as clients are deployed as a library in various apps
// and the failure of Psiphon may not be a failure for the app process.
//
// Instead, errors are logged to the getValueLogger and getValue leaves the
// target unset, which will result in the caller getting and using a zero
// value of the requested type.
func (p *parametersSnapshot) getValue(name string, target interface{}) {

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

// ParametersAccessor provides consistent, atomic access to  parameter values.
// Any customizations are applied transparently.
type ParametersAccessor struct {
	snapshot                       *parametersSnapshot
	customNetworkLatencyMultiplier float64
}

// MakeNilParametersAccessor produces a stub ParametersAccessor which returns
// true for IsNil. This may be used where a ParametersAccessor value is
// required, but Parameters.Get may not succeed. In contexts where
// MakeNilParametersAccessor may be used, calls to ParametersAccessor must
// first check IsNil before calling accessor functions.
func MakeNilParametersAccessor() ParametersAccessor {
	return ParametersAccessor{}
}

// IsNil indicates that this ParametersAccessor is a stub and its accessor
// functions may not be called. A ParametersAccessor produced by
// Parameters.Get will never return true for IsNil and IsNil guards are not
// required for ParametersAccessors known to be produced by Parameters.Get.
func (p ParametersAccessor) IsNil() bool {
	return p.snapshot == nil
}

// Close clears internal references to large memory objects, allowing them to
// be garbage collected. Call Close when done using a ParametersAccessor,
// where memory footprint is a concern, and where the ParametersAccessor is
// not immediately going out of scope. After Close is called, all other
// ParametersAccessor functions will panic if called.
func (p ParametersAccessor) Close() {
	p.snapshot = nil
}

// Tag returns the tag associated with these parameters.
func (p ParametersAccessor) Tag() string {
	return p.snapshot.tag
}

// String returns a string parameter value.
func (p ParametersAccessor) String(name string) string {
	value := ""
	p.snapshot.getValue(name, &value)
	return value
}

func (p ParametersAccessor) Strings(name string) []string {
	value := []string{}
	p.snapshot.getValue(name, &value)
	return value
}

// Int returns an int parameter value.
func (p ParametersAccessor) Int(name string) int {
	value := int(0)
	p.snapshot.getValue(name, &value)
	return value
}

// Bool returns a bool parameter value.
func (p ParametersAccessor) Bool(name string) bool {
	value := false
	p.snapshot.getValue(name, &value)
	return value
}

// Float returns a float64 parameter value.
func (p ParametersAccessor) Float(name string) float64 {
	value := float64(0.0)
	p.snapshot.getValue(name, &value)
	return value
}

// WeightedCoinFlip returns the result of prng.FlipWeightedCoin using the
// specified float parameter as the probability input.
func (p ParametersAccessor) WeightedCoinFlip(name string) bool {
	var value float64
	p.snapshot.getValue(name, &value)
	return prng.FlipWeightedCoin(value)
}

// Duration returns a time.Duration parameter value. When the duration
// parameter has the useNetworkLatencyMultiplier flag, the
// NetworkLatencyMultiplier is applied to the returned value.
func (p ParametersAccessor) Duration(name string) time.Duration {
	value := time.Duration(0)
	p.snapshot.getValue(name, &value)

	defaultParameter, ok := defaultParameters[name]
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
func (p ParametersAccessor) TunnelProtocols(name string) protocol.TunnelProtocols {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultParameters[name]
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

// LabeledTunnelProtocols returns a protocol.TunnelProtocols parameter value
// corresponding to the specified labeled set and label value. The return
// value is nil when no set is found.
func (p ParametersAccessor) LabeledTunnelProtocols(name, label string) protocol.TunnelProtocols {
	var value protocol.LabeledTunnelProtocols
	p.snapshot.getValue(name, &value)
	return value[label]
}

// TLSProfiles returns a protocol.TLSProfiles parameter value.
// If there is a corresponding Probability value, a weighted coin flip
// will be performed and, depending on the result, the value or the
// parameter default will be returned.
func (p ParametersAccessor) TLSProfiles(name string) protocol.TLSProfiles {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultParameters[name]
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
func (p ParametersAccessor) LabeledTLSProfiles(name, label string) protocol.TLSProfiles {
	var value protocol.LabeledTLSProfiles
	p.snapshot.getValue(name, &value)
	return value[label]
}

// QUICVersions returns a protocol.QUICVersions parameter value.
// If there is a corresponding Probability value, a weighted coin flip
// will be performed and, depending on the result, the value or the
// parameter default will be returned.
func (p ParametersAccessor) QUICVersions(name string) protocol.QUICVersions {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultParameters[name]
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
func (p ParametersAccessor) LabeledQUICVersions(name, label string) protocol.QUICVersions {
	value := protocol.LabeledQUICVersions{}
	p.snapshot.getValue(name, &value)
	return value[label]
}

// TransferURLs returns a TransferURLs parameter value.
func (p ParametersAccessor) TransferURLs(name string) TransferURLs {
	value := TransferURLs{}
	p.snapshot.getValue(name, &value)
	return value
}

// RateLimits returns a common.RateLimits parameter value.
func (p ParametersAccessor) RateLimits(name string) common.RateLimits {
	value := common.RateLimits{}
	p.snapshot.getValue(name, &value)
	return value
}

// HTTPHeaders returns an http.Header parameter value.
func (p ParametersAccessor) HTTPHeaders(name string) http.Header {
	value := make(http.Header)
	p.snapshot.getValue(name, &value)
	return value
}

// CustomTLSProfileNames returns the CustomTLSProfile.Name fields for
// each profile in the CustomTLSProfiles parameter value.
func (p ParametersAccessor) CustomTLSProfileNames() []string {
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
func (p ParametersAccessor) CustomTLSProfile(name string) *protocol.CustomTLSProfile {
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
func (p ParametersAccessor) KeyValues(name string) KeyValues {
	value := KeyValues{}
	p.snapshot.getValue(name, &value)
	return value
}

// BPFProgram returns an assembled BPF program corresponding to a
// BPFProgramSpec parameter value. Returns nil in the case of any empty
// program.
func (p ParametersAccessor) BPFProgram(name string) (bool, string, []bpf.RawInstruction) {
	var value *BPFProgramSpec
	p.snapshot.getValue(name, &value)
	if value == nil {
		return false, "", nil
	}
	// Validation checks that Assemble is successful.
	rawInstructions, _ := value.Assemble()
	return true, value.Name, rawInstructions
}

// PacketManipulationSpecs returns a PacketManipulationSpecs parameter value.
func (p ParametersAccessor) PacketManipulationSpecs(name string) PacketManipulationSpecs {
	value := PacketManipulationSpecs{}
	p.snapshot.getValue(name, &value)
	return value
}

// ProtocolPacketManipulations returns a ProtocolPacketManipulations parameter value.
func (p ParametersAccessor) ProtocolPacketManipulations(name string) ProtocolPacketManipulations {
	value := make(ProtocolPacketManipulations)
	p.snapshot.getValue(name, &value)
	return value
}

// RegexStrings returns a RegexStrings parameter value.
func (p ParametersAccessor) RegexStrings(name string) RegexStrings {
	value := RegexStrings{}
	p.snapshot.getValue(name, &value)
	return value
}

// FrontingSpecs returns a FrontingSpecs parameter value.
func (p ParametersAccessor) FrontingSpecs(name string) FrontingSpecs {
	value := FrontingSpecs{}
	p.snapshot.getValue(name, &value)
	return value
}

// TunnelProtocolPortLists returns a TunnelProtocolPortLists parameter value.
func (p ParametersAccessor) TunnelProtocolPortLists(name string) TunnelProtocolPortLists {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultParameters[name]
			if ok {
				defaultValue, ok := defaultParameter.value.(TunnelProtocolPortLists)
				if ok {
					value := make(TunnelProtocolPortLists)
					for tunnelProtocol, portLists := range defaultValue {
						value[tunnelProtocol] = portLists
					}
					return value
				}
			}
		}
	}

	value := make(TunnelProtocolPortLists)
	p.snapshot.getValue(name, &value)
	return value
}

// LabeledCIDRs returns a CIDR string list parameter value corresponding to
// the specified labeled set and label value. The return value is nil when no
// set is found.
func (p ParametersAccessor) LabeledCIDRs(name, label string) []string {
	value := LabeledCIDRs{}
	p.snapshot.getValue(name, &value)
	return value[label]
}

// ProtocolTransformSpecs returns a transforms.Specs parameter value.
func (p ParametersAccessor) ProtocolTransformSpecs(name string) transforms.Specs {
	value := transforms.Specs{}
	p.snapshot.getValue(name, &value)
	return value
}

// ProtocolTransformScopedSpecNames returns a transforms.ScopedSpecNames
// parameter value.
func (p ParametersAccessor) ProtocolTransformScopedSpecNames(name string) transforms.ScopedSpecNames {
	value := transforms.ScopedSpecNames{}
	p.snapshot.getValue(name, &value)
	return value
}

// ConjureTransports returns a protocol.ConjureTransports parameter value. If
// there is a corresponding Probability value, a weighted coin flip will be
// performed and, depending on the result, the value or the parameter default
// will be returned.
func (p ParametersAccessor) ConjureTransports(name string) protocol.ConjureTransports {

	probabilityName := name + "Probability"
	_, ok := p.snapshot.parameters[probabilityName]
	if ok {
		probabilityValue := float64(1.0)
		p.snapshot.getValue(probabilityName, &probabilityValue)
		if !prng.FlipWeightedCoin(probabilityValue) {
			defaultParameter, ok := defaultParameters[name]
			if ok {
				defaultValue, ok := defaultParameter.value.(protocol.ConjureTransports)
				if ok {
					value := make(protocol.ConjureTransports, len(defaultValue))
					copy(value, defaultValue)
					return value
				}
			}
		}
	}

	value := protocol.ConjureTransports{}
	p.snapshot.getValue(name, &value)
	return value
}

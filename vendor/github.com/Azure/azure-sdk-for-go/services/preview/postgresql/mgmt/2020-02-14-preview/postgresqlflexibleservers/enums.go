package postgresqlflexibleservers

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

// ConfigurationDataType enumerates the values for configuration data type.
type ConfigurationDataType string

const (
	// Boolean ...
	Boolean ConfigurationDataType = "Boolean"
	// Enumeration ...
	Enumeration ConfigurationDataType = "Enumeration"
	// Integer ...
	Integer ConfigurationDataType = "Integer"
	// Numeric ...
	Numeric ConfigurationDataType = "Numeric"
)

// PossibleConfigurationDataTypeValues returns an array of possible values for the ConfigurationDataType const type.
func PossibleConfigurationDataTypeValues() []ConfigurationDataType {
	return []ConfigurationDataType{Boolean, Enumeration, Integer, Numeric}
}

// CreateMode enumerates the values for create mode.
type CreateMode string

const (
	// Default ...
	Default CreateMode = "Default"
	// PointInTimeRestore ...
	PointInTimeRestore CreateMode = "PointInTimeRestore"
)

// PossibleCreateModeValues returns an array of possible values for the CreateMode const type.
func PossibleCreateModeValues() []CreateMode {
	return []CreateMode{Default, PointInTimeRestore}
}

// HAEnabledEnum enumerates the values for ha enabled enum.
type HAEnabledEnum string

const (
	// Disabled ...
	Disabled HAEnabledEnum = "Disabled"
	// Enabled ...
	Enabled HAEnabledEnum = "Enabled"
)

// PossibleHAEnabledEnumValues returns an array of possible values for the HAEnabledEnum const type.
func PossibleHAEnabledEnumValues() []HAEnabledEnum {
	return []HAEnabledEnum{Disabled, Enabled}
}

// OperationOrigin enumerates the values for operation origin.
type OperationOrigin string

const (
	// NotSpecified ...
	NotSpecified OperationOrigin = "NotSpecified"
	// System ...
	System OperationOrigin = "system"
	// User ...
	User OperationOrigin = "user"
)

// PossibleOperationOriginValues returns an array of possible values for the OperationOrigin const type.
func PossibleOperationOriginValues() []OperationOrigin {
	return []OperationOrigin{NotSpecified, System, User}
}

// ResourceIdentityType enumerates the values for resource identity type.
type ResourceIdentityType string

const (
	// SystemAssigned ...
	SystemAssigned ResourceIdentityType = "SystemAssigned"
)

// PossibleResourceIdentityTypeValues returns an array of possible values for the ResourceIdentityType const type.
func PossibleResourceIdentityTypeValues() []ResourceIdentityType {
	return []ResourceIdentityType{SystemAssigned}
}

// ServerHAState enumerates the values for server ha state.
type ServerHAState string

const (
	// CreatingStandby ...
	CreatingStandby ServerHAState = "CreatingStandby"
	// FailingOver ...
	FailingOver ServerHAState = "FailingOver"
	// Healthy ...
	Healthy ServerHAState = "Healthy"
	// NotEnabled ...
	NotEnabled ServerHAState = "NotEnabled"
	// RemovingStandby ...
	RemovingStandby ServerHAState = "RemovingStandby"
	// ReplicatingData ...
	ReplicatingData ServerHAState = "ReplicatingData"
)

// PossibleServerHAStateValues returns an array of possible values for the ServerHAState const type.
func PossibleServerHAStateValues() []ServerHAState {
	return []ServerHAState{CreatingStandby, FailingOver, Healthy, NotEnabled, RemovingStandby, ReplicatingData}
}

// ServerPublicNetworkAccessState enumerates the values for server public network access state.
type ServerPublicNetworkAccessState string

const (
	// ServerPublicNetworkAccessStateDisabled ...
	ServerPublicNetworkAccessStateDisabled ServerPublicNetworkAccessState = "Disabled"
	// ServerPublicNetworkAccessStateEnabled ...
	ServerPublicNetworkAccessStateEnabled ServerPublicNetworkAccessState = "Enabled"
)

// PossibleServerPublicNetworkAccessStateValues returns an array of possible values for the ServerPublicNetworkAccessState const type.
func PossibleServerPublicNetworkAccessStateValues() []ServerPublicNetworkAccessState {
	return []ServerPublicNetworkAccessState{ServerPublicNetworkAccessStateDisabled, ServerPublicNetworkAccessStateEnabled}
}

// ServerState enumerates the values for server state.
type ServerState string

const (
	// ServerStateDisabled ...
	ServerStateDisabled ServerState = "Disabled"
	// ServerStateDropping ...
	ServerStateDropping ServerState = "Dropping"
	// ServerStateReady ...
	ServerStateReady ServerState = "Ready"
	// ServerStateStarting ...
	ServerStateStarting ServerState = "Starting"
	// ServerStateStopped ...
	ServerStateStopped ServerState = "Stopped"
	// ServerStateStopping ...
	ServerStateStopping ServerState = "Stopping"
	// ServerStateUpdating ...
	ServerStateUpdating ServerState = "Updating"
)

// PossibleServerStateValues returns an array of possible values for the ServerState const type.
func PossibleServerStateValues() []ServerState {
	return []ServerState{ServerStateDisabled, ServerStateDropping, ServerStateReady, ServerStateStarting, ServerStateStopped, ServerStateStopping, ServerStateUpdating}
}

// ServerVersion enumerates the values for server version.
type ServerVersion string

const (
	// OneOne ...
	OneOne ServerVersion = "11"
	// OneTwo ...
	OneTwo ServerVersion = "12"
)

// PossibleServerVersionValues returns an array of possible values for the ServerVersion const type.
func PossibleServerVersionValues() []ServerVersion {
	return []ServerVersion{OneOne, OneTwo}
}

// SkuTier enumerates the values for sku tier.
type SkuTier string

const (
	// Burstable ...
	Burstable SkuTier = "Burstable"
	// GeneralPurpose ...
	GeneralPurpose SkuTier = "GeneralPurpose"
	// MemoryOptimized ...
	MemoryOptimized SkuTier = "MemoryOptimized"
)

// PossibleSkuTierValues returns an array of possible values for the SkuTier const type.
func PossibleSkuTierValues() []SkuTier {
	return []SkuTier{Burstable, GeneralPurpose, MemoryOptimized}
}
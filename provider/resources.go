// Copyright 2016-2018, Pulumi Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nsxt

import (
	"unicode"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/pulumi/pulumi-terraform-bridge/v2/pkg/tfbridge"
	"github.com/pulumi/pulumi/sdk/v2/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v2/go/common/tokens"
	"github.com/vmware/terraform-provider-nsxt/nsxt"
)

// all of the token components used below.
const (
	// packages:
	mainPkg = "nsxt"
	// modules:
	nsxtMod = "index" // the y module
)

// nsxtMember manufactures a type token for the package and the given module and type.
func nsxtMember(mod string, mem string) tokens.ModuleMember {
	return tokens.ModuleMember(mainPkg + ":" + mod + ":" + mem)
}

// nsxtType manufactures a type token for the package and the given module and type.
func nsxtType(mod string, typ string) tokens.Type {
	return tokens.Type(nsxtMember(mod, typ))
}

// nsxtDataSource manufactures a standard resource token given a module and resource name.  It
// automatically uses the main package and names the file by simply lower casing the data source's
// first character.
func nsxtDataSource(mod string, res string) tokens.ModuleMember {
	fn := string(unicode.ToLower(rune(res[0]))) + res[1:]
	return nsxtMember(mod+"/"+fn, res)
}

// nsxtResource manufactures a standard resource token given a module and resource name.  It
// automatically uses the main package and names the file by simply lower casing the resource's
// first character.
func nsxtResource(mod string, res string) tokens.Type {
	fn := string(unicode.ToLower(rune(res[0]))) + res[1:]
	return nsxtType(mod+"/"+fn, res)
}

// boolRef returns a reference to the bool argument.
func boolRef(b bool) *bool {
	return &b
}

// stringValue gets a string value from a property map if present, else ""
func stringValue(vars resource.PropertyMap, prop resource.PropertyKey) string {
	val, ok := vars[prop]
	if ok && val.IsString() {
		return val.StringValue()
	}
	return ""
}

// preConfigureCallback is called before the providerConfigure function of the underlying provider.
// It should validate that the provider can be configured, and provide actionable errors in the case
// it cannot be. Configuration variables can be read from `vars` using the `stringValue` function -
// for example `stringValue(vars, "accessKey")`.
func preConfigureCallback(vars resource.PropertyMap, c *terraform.ResourceConfig) error {
	return nil
}

// managedByPulumi is a default used for some managed resources, in the absence of something more meaningful.
var managedByPulumi = &tfbridge.DefaultInfo{Value: "Managed by Pulumi"}

// Provider returns additional overlaid schema and metadata associated with the provider..
func Provider() tfbridge.ProviderInfo {
	// Instantiate the Terraform provider
	p := nsxt.Provider().(*schema.Provider)

	// Create a Pulumi provider mapping
	prov := tfbridge.ProviderInfo{
		P:           p,
		Name:        "nsxt",
		Description: "A Pulumi package for creating and managing nsxt cloud resources.",
		Keywords:    []string{"pulumi", "nsxt"},
		License:     "Apache-2.0",
		Homepage:    "https://pulumi.io",
		Repository:  "https://github.com/pulumi/pulumi-nsxt",
		Config: map[string]*tfbridge.SchemaInfo{
			"allow_unverified_ssl": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_ALLOW_UNVERIFIED_SSL"},
				},
			},
			"username": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_USERNAME"},
				},
			},
			"password": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_PASSWORD"},
				},
			},
			"remote_auth": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_REMOTE_AUTH"},
				},
			},
			"host": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_MANAGER_HOST"},
				},
			},
			"client_auth_cert_file": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_CLIENT_AUTH_CERT_FILE"},
				},
			},
			"client_auth_key_file": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_CLIENT_AUTH_KEY_FILE"},
				},
			},
			"ca_file": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_CA_FILE"},
				},
			},
			"max_retries": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_MAX_RETRIES"},
				},
			},
			"retry_min_delay": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_RETRY_MIN_DELAY"},
				},
			},
			"retry_max_delay": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_RETRY_MAX_DELAY"},
				},
			},
			"retry_on_status_codes": {
			},
			"tolerate_partial_success": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_TOLERATE_PARTIAL_SUCCESS"},
				},
			},
			"vmc_auth_host": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_VMC_AUTH_HOST"},
				},
			},
			"vmc_token": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_VMC_TOKEN"},
				},
			},
			"enforcement_point": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_POLICY_ENFORCEMENT_POINT"},
				},
			},
			"global_manager": {
				Default: &tfbridge.DefaultInfo{
					EnvVars: []string{"NSXT_GLOBAL_MANAGER"},
				},
			},
		},
		PreConfigureCallback: preConfigureCallback,
		Resources: map[string]*tfbridge.ResourceInfo{
			"nsxt_dhcp_relay_profile":                      {Tok: nsxtResource(nsxtMod, "DHCPRelayProfile")},
			"nsxt_dhcp_relay_service":                      {Tok: nsxtResource(nsxtMod, "DHCPRelayService")},
			"nsxt_dhcp_server_profile":                     {Tok: nsxtResource(nsxtMod, "DHCPServerProfile")},
			"nsxt_logical_dhcp_server":                     {Tok: nsxtResource(nsxtMod, "LogicalDHCPerver")},
			"nsxt_dhcp_server_ip_pool":                     {Tok: nsxtResource(nsxtMod, "DHCPServerIPPool")},
			"nsxt_logical_switch":                          {Tok: nsxtResource(nsxtMod, "LogicalSwitch")},
			"nsxt_vlan_logical_switch":                     {Tok: nsxtResource(nsxtMod, "VlanLogicalSwitch")},
			"nsxt_logical_dhcp_port":                       {Tok: nsxtResource(nsxtMod, "LogicalDHCPPort")},
			"nsxt_logical_port":                            {Tok: nsxtResource(nsxtMod, "LogicalPort")},
			"nsxt_logical_tier0_router":                    {Tok: nsxtResource(nsxtMod, "LogicalTier0Router")},
			"nsxt_logical_tier1_router":                    {Tok: nsxtResource(nsxtMod, "LogicalTier1Router")},
			"nsxt_logical_router_centralized_service_port": {Tok: nsxtResource(nsxtMod, "LogicalRouterCentralizedServicePort")},
			"nsxt_logical_router_downlink_port":            {Tok: nsxtResource(nsxtMod, "LogicalRouterDownlinkPort")},
			"nsxt_logical_router_link_port_on_tier0":       {Tok: nsxtResource(nsxtMod, "LogicalRouterLinkPortOnTier0")},
			"nsxt_logical_router_link_port_on_tier1":       {Tok: nsxtResource(nsxtMod, "LogicalRouterLinkPortOnTier1")},
			"nsxt_ip_discovery_switching_profile":          {Tok: nsxtResource(nsxtMod, "IPDiscoverySwitchingProfile")},
			"nsxt_mac_management_switching_profile":        {Tok: nsxtResource(nsxtMod, "MACManagementSwitchingProfile")},
			"nsxt_qos_switching_profile":                   {Tok: nsxtResource(nsxtMod, "QOSSwitchingProfile")},
			"nsxt_spoofguard_switching_profile":            {Tok: nsxtResource(nsxtMod, "SpoofguardSwitchingProfile")},
			"nsxt_switch_security_switching_profile":       {Tok: nsxtResource(nsxtMod, "SwitchSecuritySwitchingProfile")},
			"nsxt_l4_port_set_ns_service":                  {Tok: nsxtResource(nsxtMod, "L4PortSetNSService")},
			"nsxt_algorithm_type_ns_service":               {Tok: nsxtResource(nsxtMod, "AlgorithmTypeNSService")},
			"nsxt_icmp_type_ns_service":                    {Tok: nsxtResource(nsxtMod, "ICMPTypeNSService")},
			"nsxt_igmp_type_ns_service":                    {Tok: nsxtResource(nsxtMod, "IGMPTypeNSService")},
			"nsxt_ether_type_ns_service":                   {Tok: nsxtResource(nsxtMod, "EtherTypeNSService")},
			"nsxt_ip_protocol_ns_service":                  {Tok: nsxtResource(nsxtMod, "IPProtocolNSService")},
			"nsxt_ns_service_group":                        {Tok: nsxtResource(nsxtMod, "NSServiceGroup")},
			"nsxt_ns_group":                                {Tok: nsxtResource(nsxtMod, "NSroup")},
			"nsxt_firewall_section":                        {Tok: nsxtResource(nsxtMod, "FirewallSection")},
			"nsxt_nat_rule":                                {Tok: nsxtResource(nsxtMod, "NATRule")},
			"nsxt_ip_block":                                {Tok: nsxtResource(nsxtMod, "IPBlock")},
			"nsxt_ip_block_subnet":                         {Tok: nsxtResource(nsxtMod, "IPBlockSubnet")},
			"nsxt_ip_pool":                                 {Tok: nsxtResource(nsxtMod, "IPPool")},
			"nsxt_ip_pool_allocation_ip_address":           {Tok: nsxtResource(nsxtMod, "IPPoolAllocationIPAddress")},
			"nsxt_ip_set":                                  {Tok: nsxtResource(nsxtMod, "IPSet")},
			"nsxt_static_route":                            {Tok: nsxtResource(nsxtMod, "StaticRoute")},
			"nsxt_vm_tags":                                 {Tok: nsxtResource(nsxtMod, "VMTags")},
			"nsxt_lb_icmp_monitor":                         {Tok: nsxtResource(nsxtMod, "LBICMPMonitor")},
			"nsxt_lb_tcp_monitor":                          {Tok: nsxtResource(nsxtMod, "LBTCPMonitor")},
			"nsxt_lb_udp_monitor":                          {Tok: nsxtResource(nsxtMod, "LBUDPMonitor")},
			"nsxt_lb_http_monitor":                         {Tok: nsxtResource(nsxtMod, "LBHTTPMonitor")},
			"nsxt_lb_https_monitor":                        {Tok: nsxtResource(nsxtMod, "LBHTTPSMonitor")},
			"nsxt_lb_passive_monitor":                      {Tok: nsxtResource(nsxtMod, "LBPassiveMonitor")},
			"nsxt_lb_pool":                                 {Tok: nsxtResource(nsxtMod, "LBPool")},
			"nsxt_lb_tcp_virtual_server":                   {Tok: nsxtResource(nsxtMod, "LBTCPVirtualServer")},
			"nsxt_lb_udp_virtual_server":                   {Tok: nsxtResource(nsxtMod, "LBUDPVirtualServer")},
			"nsxt_lb_http_virtual_server":                  {Tok: nsxtResource(nsxtMod, "LBHTTPVirtualServer")},
			"nsxt_lb_http_forwarding_rule":                 {Tok: nsxtResource(nsxtMod, "LBHTTPForwardingRule")},
			"nsxt_lb_http_request_rewrite_rule":            {Tok: nsxtResource(nsxtMod, "LBHTTPRequestRewriteRule")},
			"nsxt_lb_http_response_rewrite_rule":           {Tok: nsxtResource(nsxtMod, "LBHTTPResponseRewriteRule")},
			"nsxt_lb_cookie_persistence_profile":           {Tok: nsxtResource(nsxtMod, "LBCookiePersistenceProfile")},
			"nsxt_lb_source_ip_persistence_profile":        {Tok: nsxtResource(nsxtMod, "LBSourceIPPersistenceProfile")},
			"nsxt_lb_client_ssl_profile":                   {Tok: nsxtResource(nsxtMod, "LBClientSSLProfile")},
			"nsxt_lb_server_ssl_profile":                   {Tok: nsxtResource(nsxtMod, "LBServerSSLProfile")},
			"nsxt_lb_service":                              {Tok: nsxtResource(nsxtMod, "LBService")},
			"nsxt_lb_fast_tcp_application_profile":         {Tok: nsxtResource(nsxtMod, "LBFastTCPApplicationProfile")},
			"nsxt_lb_fast_udp_application_profile":         {Tok: nsxtResource(nsxtMod, "LBFastUDPApplicationProfile")},
			"nsxt_lb_http_application_profile":             {Tok: nsxtResource(nsxtMod, "LBHTTPApplicationProfile")},
			"nsxt_policy_tier1_gateway":                    {Tok: nsxtResource(nsxtMod, "PolicyTier1Gateway")},
			"nsxt_policy_tier1_gateway_interface":          {Tok: nsxtResource(nsxtMod, "PolicyTier1GatewayInterface")},
			"nsxt_policy_tier0_gateway":                    {Tok: nsxtResource(nsxtMod, "PolicyTier0Gateway")},
			"nsxt_policy_tier0_gateway_interface":          {Tok: nsxtResource(nsxtMod, "PolicyTier0GatewayInterface")},
			"nsxt_policy_tier0_gateway_ha_vip_config":      {Tok: nsxtResource(nsxtMod, "PolicyTier0GatewayHAVIPConfig")},
			"nsxt_policy_group":                            {Tok: nsxtResource(nsxtMod, "PolicyGroup")},
			"nsxt_policy_security_policy":                  {Tok: nsxtResource(nsxtMod, "PolicySecurityPolicy")},
			"nsxt_policy_service":                          {Tok: nsxtResource(nsxtMod, "PolicyService")},
			"nsxt_policy_gateway_policy":                   {Tok: nsxtResource(nsxtMod, "PolicyGatewayPolicy")},
			"nsxt_policy_predefined_gateway_policy":        {Tok: nsxtResource(nsxtMod, "PolicyPredefinedGatewayPolicy")},
			"nsxt_policy_predefined_security_policy":       {Tok: nsxtResource(nsxtMod, "PolicyPredefinedSecurityPolicy")},
			"nsxt_policy_segment":                          {Tok: nsxtResource(nsxtMod, "PolicySegment")},
			"nsxt_policy_vlan_segment":                     {Tok: nsxtResource(nsxtMod, "PolicyVlanSegment")},
			"nsxt_policy_static_route":                     {Tok: nsxtResource(nsxtMod, "PolicyStaticRoute")},
			"nsxt_policy_gateway_prefix_list":              {Tok: nsxtResource(nsxtMod, "PolicyGatewayPrefixList")},
			"nsxt_policy_vm_tags":                          {Tok: nsxtResource(nsxtMod, "PolicyVMTags")},
			"nsxt_policy_nat_rule":                         {Tok: nsxtResource(nsxtMod, "PolicyNatRule")},
			"nsxt_policy_ip_block":                         {Tok: nsxtResource(nsxtMod, "PolicyIPBlock")},
			"nsxt_policy_lb_pool":                          {Tok: nsxtResource(nsxtMod, "PolicyLBPool")},
			"nsxt_policy_ip_pool":                          {Tok: nsxtResource(nsxtMod, "PolicyIPPool")},
			"nsxt_policy_ip_pool_block_subnet":             {Tok: nsxtResource(nsxtMod, "PolicyIPPoolBlockSubnet")},
			"nsxt_policy_ip_pool_static_subnet":            {Tok: nsxtResource(nsxtMod, "PolicyIPPoolStaticSubnet")},
			"nsxt_policy_lb_service":                       {Tok: nsxtResource(nsxtMod, "PolicyLBService")},
			"nsxt_policy_lb_virtual_server":                {Tok: nsxtResource(nsxtMod, "PolicyLBVirtualServer")},
			"nsxt_policy_ip_address_allocation":            {Tok: nsxtResource(nsxtMod, "PolicyIPAddressAllocation")},
			"nsxt_policy_bgp_neighbor":                     {Tok: nsxtResource(nsxtMod, "PolicyBGPNeighbor")},
			"nsxt_policy_bgp_config":                       {Tok: nsxtResource(nsxtMod, "PolicyBGPConfig")},
			"nsxt_policy_dhcp_relay":                       {Tok: nsxtResource(nsxtMod, "PolicyDHCPRelay")},
			"nsxt_policy_dhcp_server":                      {Tok: nsxtResource(nsxtMod, "PolicyDHCPServer")},
			"nsxt_policy_context_profile":                  {Tok: nsxtResource(nsxtMod, "PolicyContextProfile")},
		},
		DataSources: map[string]*tfbridge.DataSourceInfo{
			"nsxt_transport_zone":                  {Tok: nsxtDataSource(nsxtMod, "getTransportZone")},
			"nsxt_switching_profile":               {Tok: nsxtDataSource(nsxtMod, "getSwitchingProfile")},
			"nsxt_logical_tier0_router":            {Tok: nsxtDataSource(nsxtMod, "getLogicalTier0Router")},
			"nsxt_logical_tier1_router":            {Tok: nsxtDataSource(nsxtMod, "getLogicalTier1Router")},
			"nsxt_mac_pool":                        {Tok: nsxtDataSource(nsxtMod, "getMACPool")},
			"nsxt_ns_group":                        {Tok: nsxtDataSource(nsxtMod, "getNSGroup")},
			"nsxt_ns_service":                      {Tok: nsxtDataSource(nsxtMod, "getNSService")},
			"nsxt_edge_cluster":                    {Tok: nsxtDataSource(nsxtMod, "getEdgeCluster")},
			"nsxt_certificate":                     {Tok: nsxtDataSource(nsxtMod, "getCertificate")},
			"nsxt_ip_pool":                         {Tok: nsxtDataSource(nsxtMod, "getIPPool")},
			"nsxt_firewall_section":                {Tok: nsxtDataSource(nsxtMod, "getFirewallSection")},
			"nsxt_management_cluster":              {Tok: nsxtDataSource(nsxtMod, "getManagementCluster")},
			"nsxt_policy_edge_cluster":             {Tok: nsxtDataSource(nsxtMod, "getPolicyEdgeCluster")},
			"nsxt_policy_edge_node":                {Tok: nsxtDataSource(nsxtMod, "getPolicyEdgeNode")},
			"nsxt_policy_tier0_gateway":            {Tok: nsxtDataSource(nsxtMod, "getPolicyTier0Gateway")},
			"nsxt_policy_tier1_gateway":            {Tok: nsxtDataSource(nsxtMod, "getPolicyTier1Gateway")},
			"nsxt_policy_service":                  {Tok: nsxtDataSource(nsxtMod, "getPolicyService")},
			"nsxt_policy_realization_info":         {Tok: nsxtDataSource(nsxtMod, "getPolicyRealizationInfo")},
			"nsxt_policy_segment_realization":      {Tok: nsxtDataSource(nsxtMod, "getPolicySegmentRealization")},
			"nsxt_policy_transport_zone":           {Tok: nsxtDataSource(nsxtMod, "getPolicyTransportZone")},
			"nsxt_policy_ip_discovery_profile":     {Tok: nsxtDataSource(nsxtMod, "getPolicyIPDiscoveryProfile")},
			"nsxt_policy_spoofguard_profile":       {Tok: nsxtDataSource(nsxtMod, "getPolicySpoofguardProfile")},
			"nsxt_policy_qos_profile":              {Tok: nsxtDataSource(nsxtMod, "getPolicyQOSProfile")},
			"nsxt_policy_ipv6_dad_profile":         {Tok: nsxtDataSource(nsxtMod, "getPolicyIPv6DadProfile")},
			"nsxt_policy_ipv6_ndra_profile":        {Tok: nsxtDataSource(nsxtMod, "getPolicyIPv6NdraProfile")},
			"nsxt_policy_gateway_qos_profile":      {Tok: nsxtDataSource(nsxtMod, "getPolicyGatewayQOSProfile")},
			"nsxt_policy_segment_security_profile": {Tok: nsxtDataSource(nsxtMod, "getPolicySegmentSecurityProfile")},
			"nsxt_policy_mac_discovery_profile":    {Tok: nsxtDataSource(nsxtMod, "getPolicyMACDiscoveryProfile")},
			"nsxt_policy_vm":                       {Tok: nsxtDataSource(nsxtMod, "getPolicyVM")},
			"nsxt_policy_lb_app_profile":           {Tok: nsxtDataSource(nsxtMod, "getPolicyLBAppProfile")},
			"nsxt_policy_lb_client_ssl_profile":    {Tok: nsxtDataSource(nsxtMod, "getPolicyLBClientSSLProfile")},
			"nsxt_policy_lb_server_ssl_profile":    {Tok: nsxtDataSource(nsxtMod, "getPolicyLBServerSSLProfile")},
			"nsxt_policy_lb_monitor":               {Tok: nsxtDataSource(nsxtMod, "getPolicyLBMonitor")},
			"nsxt_policy_certificate":              {Tok: nsxtDataSource(nsxtMod, "getPolicyCertificate")},
			"nsxt_policy_lb_persistence_profile":   {Tok: nsxtDataSource(nsxtMod, "getPolicyLBPersistenceProfile")},
			"nsxt_policy_vni_pool":                 {Tok: nsxtDataSource(nsxtMod, "getPolicyVNIPool")},
			"nsxt_policy_ip_block":                 {Tok: nsxtDataSource(nsxtMod, "getPolicyIPBlock")},
			"nsxt_policy_ip_pool":                  {Tok: nsxtDataSource(nsxtMod, "getPolicyIPPool")},
			"nsxt_policy_context_profile":          {Tok: nsxtDataSource(nsxtMod, "getPolicyContextProfile")},
			"nsxt_policy_site":                     {Tok: nsxtDataSource(nsxtMod, "getPolicySite")},
			"nsxt_policy_gateway_policy":           {Tok: nsxtDataSource(nsxtMod, "getPolicyGatewayPolicy")},
			"nsxt_policy_security_policy":          {Tok: nsxtDataSource(nsxtMod, "getPolicySecurityPolicy")},
			"nsxt_policy_group":                    {Tok: nsxtDataSource(nsxtMod, "getPolicyGroup")},
		},
		JavaScript: &tfbridge.JavaScriptInfo{
			//AsyncDataSources: true,
			// List any npm dependencies and their versions
			Dependencies: map[string]string{
				"@pulumi/pulumi":    "^2.0.0",
				"builtin-modules":   "3.0.0",
				"read-package-tree": "^5.2.1",
				"resolve":           "^1.8.1",
			},
			DevDependencies: map[string]string{
				"@types/node": "^8.0.25", // so we can access strongly typed node definitions.
				"@types/mime": "^2.0.0",
			},
			// See the documentation for tfbridge.OverlayInfo for how to lay out this
			// section, or refer to the AWS provider. Delete this section if there are
			// no overlay files.
			//Overlay: &tfbridge.OverlayInfo{},
		},
		Python: &tfbridge.PythonInfo{
			// List any Python dependencies and their version ranges
			Requires: map[string]string{
				"pulumi": ">=2.0.0,<3.0.0",
			},
		},
		CSharp: &tfbridge.CSharpInfo{
			PackageReferences: map[string]string{
				"Pulumi":                       "2.*",
				"System.Collections.Immutable": "1.6.0",
			},
		},
	}

	// For all resources with name properties, we will add an auto-name property.  Make sure to skip those that
	// already have a name mapping entry, since those may have custom overrides set above (e.g., for length).
	const nameProperty = "name"
	for resname, res := range prov.Resources {
		if schema := p.ResourcesMap[resname]; schema != nil {
			// Only apply auto-name to input properties (Optional || Required) named `name`
			if tfs, has := schema.Schema[nameProperty]; has && (tfs.Optional || tfs.Required) {
				if _, hasfield := res.Fields[nameProperty]; !hasfield {
					if res.Fields == nil {
						res.Fields = make(map[string]*tfbridge.SchemaInfo)
					}
					res.Fields[nameProperty] = tfbridge.AutoName(nameProperty, 255)
				}
			}
		}
	}

	return prov
}

# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

_SNAKE_TO_CAMEL_CASE_TABLE = {
    "access_list_control": "accessListControl",
    "access_log_enabled": "accessLogEnabled",
    "access_vlan_id": "accessVlanId",
    "active_monitor_id": "activeMonitorId",
    "active_monitor_path": "activeMonitorPath",
    "address_binding_whitelist_enabled": "addressBindingWhitelistEnabled",
    "address_bindings": "addressBindings",
    "admin_state": "adminState",
    "advanced_config": "advancedConfig",
    "advertise_config_revision": "advertiseConfigRevision",
    "advertise_connected_routes": "advertiseConnectedRoutes",
    "advertise_lb_snat_ip_routes": "advertiseLbSnatIpRoutes",
    "advertise_lb_vip_routes": "advertiseLbVipRoutes",
    "advertise_nat_routes": "advertiseNatRoutes",
    "advertise_static_routes": "advertiseStaticRoutes",
    "algorithm_entries": "algorithmEntries",
    "allocation_id": "allocationId",
    "allocation_ip": "allocationIp",
    "allocation_ranges": "allocationRanges",
    "allow_as_in": "allowAsIn",
    "app_ids": "appIds",
    "application_profile_id": "applicationProfileId",
    "application_profile_path": "applicationProfilePath",
    "applied_tos": "appliedTos",
    "arp_bindings_limit": "arpBindingsLimit",
    "arp_snooping_enabled": "arpSnoopingEnabled",
    "attached_logical_port_id": "attachedLogicalPortId",
    "auto_assign_gateway": "autoAssignGateway",
    "bfd_config": "bfdConfig",
    "bgp_config": "bgpConfig",
    "bgp_path": "bgpPath",
    "block_client_dhcp": "blockClientDhcp",
    "block_id": "blockId",
    "block_non_ip": "blockNonIp",
    "block_path": "blockPath",
    "block_server_dhcp": "blockServerDhcp",
    "body_conditions": "bodyConditions",
    "bpdu_filter_enabled": "bpduFilterEnabled",
    "bpdu_filter_whitelists": "bpduFilterWhitelists",
    "certificate_chain_depth": "certificateChainDepth",
    "class_of_service": "classOfService",
    "client_certificate_id": "clientCertificateId",
    "client_ssl": "clientSsl",
    "close_timeout": "closeTimeout",
    "connectivity_path": "connectivityPath",
    "cookie_conditions": "cookieConditions",
    "cookie_fallback": "cookieFallback",
    "cookie_garble": "cookieGarble",
    "cookie_mode": "cookieMode",
    "cookie_name": "cookieName",
    "data_length": "dataLength",
    "default_pool_member_port": "defaultPoolMemberPort",
    "default_pool_member_ports": "defaultPoolMemberPorts",
    "default_rule": "defaultRule",
    "default_rule_logging": "defaultRuleLogging",
    "default_rules": "defaultRules",
    "default_service": "defaultService",
    "destination_networks": "destinationNetworks",
    "destination_port": "destinationPort",
    "destination_ports": "destinationPorts",
    "dhcp_config_path": "dhcpConfigPath",
    "dhcp_generic_options": "dhcpGenericOptions",
    "dhcp_option121s": "dhcpOption121s",
    "dhcp_profile_id": "dhcpProfileId",
    "dhcp_relay_profile_id": "dhcpRelayProfileId",
    "dhcp_server_id": "dhcpServerId",
    "dhcp_server_ip": "dhcpServerIp",
    "dhcp_snooping_enabled": "dhcpSnoopingEnabled",
    "discovery_profile": "discoveryProfile",
    "display_name": "displayName",
    "dns_name_servers": "dnsNameServers",
    "dns_nameservers": "dnsNameservers",
    "dns_suffix": "dnsSuffix",
    "domain_name": "domainName",
    "dscp_priority": "dscpPriority",
    "dscp_trusted": "dscpTrusted",
    "edge_cluster_id": "edgeClusterId",
    "edge_cluster_member_indexes": "edgeClusterMemberIndexes",
    "edge_cluster_path": "edgeClusterPath",
    "edge_node_path": "edgeNodePath",
    "egress_qos_profile_path": "egressQosProfilePath",
    "egress_rate_shaper": "egressRateShaper",
    "enable_firewall": "enableFirewall",
    "enable_pim": "enablePim",
    "enable_router_advertisement": "enableRouterAdvertisement",
    "enable_standby_relocation": "enableStandbyRelocation",
    "error_log_level": "errorLogLevel",
    "error_threshold": "errorThreshold",
    "ether_type": "etherType",
    "ether_type_entries": "etherTypeEntries",
    "extended_criteria": "extendedCriteria",
    "failover_mode": "failoverMode",
    "fall_count": "fallCount",
    "firewall_match": "firewallMatch",
    "firewall_sections": "firewallSections",
    "force_whitelisting": "forceWhitelisting",
    "gateway_ip": "gatewayIp",
    "gateway_path": "gatewayPath",
    "graceful_restart_mode": "gracefulRestartMode",
    "graceful_restart_stale_route_timer": "gracefulRestartStaleRouteTimer",
    "graceful_restart_timer": "gracefulRestartTimer",
    "ha_flow_mirroring": "haFlowMirroring",
    "ha_mode": "haMode",
    "ha_persistence_mirroring": "haPersistenceMirroring",
    "header_conditions": "headerConditions",
    "header_rewrite_action": "headerRewriteAction",
    "high_availability_mode": "highAvailabilityMode",
    "hold_down_time": "holdDownTime",
    "http_redirect_action": "httpRedirectAction",
    "http_redirect_to": "httpRedirectTo",
    "http_redirect_to_https": "httpRedirectToHttps",
    "http_reject_action": "httpRejectAction",
    "icmp_code": "icmpCode",
    "icmp_entries": "icmpEntries",
    "icmp_type": "icmpType",
    "idle_timeout": "idleTimeout",
    "igmp_entries": "igmpEntries",
    "ingress_broadcast_rate_shaper": "ingressBroadcastRateShaper",
    "ingress_qos_profile_path": "ingressQosProfilePath",
    "ingress_rate_shaper": "ingressRateShaper",
    "insert_before": "insertBefore",
    "insert_mode_params": "insertModeParams",
    "instance_id": "instanceId",
    "inter_sr_ibgp": "interSrIbgp",
    "internal_transit_subnets": "internalTransitSubnets",
    "intersite_config": "intersiteConfig",
    "ip_address": "ipAddress",
    "ip_addresses": "ipAddresses",
    "ip_conditions": "ipConditions",
    "ip_pool_id": "ipPoolId",
    "ip_protocol_entries": "ipProtocolEntries",
    "ip_ranges": "ipRanges",
    "ipv6_dad_profile_path": "ipv6DadProfilePath",
    "ipv6_ndra_profile_path": "ipv6NdraProfilePath",
    "is_default": "isDefault",
    "is_secure": "isSecure",
    "keep_alive_time": "keepAliveTime",
    "l2_extension": "l2Extension",
    "l4_port_set_entries": "l4PortSetEntries",
    "lease_time": "leaseTime",
    "linked_logical_router_port_id": "linkedLogicalRouterPortId",
    "linked_logical_switch_port_id": "linkedLogicalSwitchPortId",
    "local_as_num": "localAsNum",
    "locale_service_id": "localeServiceId",
    "locale_services": "localeServices",
    "log_significant_event_only": "logSignificantEventOnly",
    "logical_dhcp_server_id": "logicalDhcpServerId",
    "logical_port_tags": "logicalPortTags",
    "logical_router_id": "logicalRouterId",
    "logical_switch_id": "logicalSwitchId",
    "mac_address": "macAddress",
    "mac_change_allowed": "macChangeAllowed",
    "mac_learning": "macLearning",
    "mac_pool_id": "macPoolId",
    "match_destination_network": "matchDestinationNetwork",
    "match_source_network": "matchSourceNetwork",
    "match_strategy": "matchStrategy",
    "max_concurrent_connections": "maxConcurrentConnections",
    "max_fails": "maxFails",
    "max_new_connection_rate": "maxNewConnectionRate",
    "maximum_hop_limit": "maximumHopLimit",
    "member_group": "memberGroup",
    "membership_criterias": "membershipCriterias",
    "method_conditions": "methodConditions",
    "min_active_members": "minActiveMembers",
    "monitor_port": "monitorPort",
    "multipath_relax": "multipathRelax",
    "nat_pass": "natPass",
    "neighbor_address": "neighborAddress",
    "next_hops": "nextHops",
    "nsx_id": "nsxId",
    "overlay_id": "overlayId",
    "passive_monitor_id": "passiveMonitorId",
    "passive_monitor_path": "passiveMonitorPath",
    "persistence_profile_id": "persistenceProfileId",
    "persistence_profile_path": "persistenceProfilePath",
    "persistence_shared": "persistenceShared",
    "pool_allocation": "poolAllocation",
    "pool_id": "poolId",
    "pool_path": "poolPath",
    "prefer_server_ciphers": "preferServerCiphers",
    "preferred_edge_paths": "preferredEdgePaths",
    "purge_when_full": "purgeWhenFull",
    "qos_profile": "qosProfile",
    "rate_limits": "rateLimits",
    "redistribution_config": "redistributionConfig",
    "remote_as_num": "remoteAsNum",
    "replication_mode": "replicationMode",
    "request_body": "requestBody",
    "request_body_size": "requestBodySize",
    "request_header_conditions": "requestHeaderConditions",
    "request_header_size": "requestHeaderSize",
    "request_headers": "requestHeaders",
    "request_method": "requestMethod",
    "request_url": "requestUrl",
    "request_version": "requestVersion",
    "response_body": "responseBody",
    "response_header_conditions": "responseHeaderConditions",
    "response_status_codes": "responseStatusCodes",
    "response_timeout": "responseTimeout",
    "rise_count": "riseCount",
    "route_advertisement_rules": "routeAdvertisementRules",
    "route_advertisement_types": "routeAdvertisementTypes",
    "route_aggregations": "routeAggregations",
    "route_filterings": "routeFilterings",
    "rule_ids": "ruleIds",
    "rule_priority": "rulePriority",
    "section_type": "sectionType",
    "security_profile": "securityProfile",
    "segment_path": "segmentPath",
    "select_pool_action": "selectPoolAction",
    "sequence_number": "sequenceNumber",
    "server_addresses": "serverAddresses",
    "server_auth": "serverAuth",
    "server_auth_ca_ids": "serverAuthCaIds",
    "server_auth_crl_ids": "serverAuthCrlIds",
    "server_ssl": "serverSsl",
    "service_bindings": "serviceBindings",
    "service_path": "servicePath",
    "session_cache_enabled": "sessionCacheEnabled",
    "session_cache_timeout": "sessionCacheTimeout",
    "site_path": "sitePath",
    "snat_translation": "snatTranslation",
    "sorry_pool_id": "sorryPoolId",
    "sorry_pool_path": "sorryPoolPath",
    "source_addresses": "sourceAddresses",
    "source_networks": "sourceNetworks",
    "source_ports": "sourcePorts",
    "switching_profile_ids": "switchingProfileIds",
    "tcp_conditions": "tcpConditions",
    "tcp_multiplexing_enabled": "tcpMultiplexingEnabled",
    "tcp_multiplexing_number": "tcpMultiplexingNumber",
    "tcp_strict": "tcpStrict",
    "tier0_id": "tier0Id",
    "tier0_path": "tier0Path",
    "transit_subnets": "transitSubnets",
    "translated_network": "translatedNetwork",
    "translated_networks": "translatedNetworks",
    "translated_ports": "translatedPorts",
    "transport_zone_id": "transportZoneId",
    "transport_zone_path": "transportZonePath",
    "uri_arguments_conditions": "uriArgumentsConditions",
    "uri_conditions": "uriConditions",
    "uri_rewrite_action": "uriRewriteAction",
    "url_category": "urlCategory",
    "urpf_mode": "urpfMode",
    "version_condition": "versionCondition",
    "virtual_server_ids": "virtualServerIds",
    "vlan_ids": "vlanIds",
    "vm_tools_enabled": "vmToolsEnabled",
    "vrf_config": "vrfConfig",
    "warning_threshold": "warningThreshold",
    "x_forwarded_for": "xForwardedFor",
}

_CAMEL_TO_SNAKE_CASE_TABLE = {
    "accessListControl": "access_list_control",
    "accessLogEnabled": "access_log_enabled",
    "accessVlanId": "access_vlan_id",
    "activeMonitorId": "active_monitor_id",
    "activeMonitorPath": "active_monitor_path",
    "addressBindingWhitelistEnabled": "address_binding_whitelist_enabled",
    "addressBindings": "address_bindings",
    "adminState": "admin_state",
    "advancedConfig": "advanced_config",
    "advertiseConfigRevision": "advertise_config_revision",
    "advertiseConnectedRoutes": "advertise_connected_routes",
    "advertiseLbSnatIpRoutes": "advertise_lb_snat_ip_routes",
    "advertiseLbVipRoutes": "advertise_lb_vip_routes",
    "advertiseNatRoutes": "advertise_nat_routes",
    "advertiseStaticRoutes": "advertise_static_routes",
    "algorithmEntries": "algorithm_entries",
    "allocationId": "allocation_id",
    "allocationIp": "allocation_ip",
    "allocationRanges": "allocation_ranges",
    "allowAsIn": "allow_as_in",
    "appIds": "app_ids",
    "applicationProfileId": "application_profile_id",
    "applicationProfilePath": "application_profile_path",
    "appliedTos": "applied_tos",
    "arpBindingsLimit": "arp_bindings_limit",
    "arpSnoopingEnabled": "arp_snooping_enabled",
    "attachedLogicalPortId": "attached_logical_port_id",
    "autoAssignGateway": "auto_assign_gateway",
    "bfdConfig": "bfd_config",
    "bgpConfig": "bgp_config",
    "bgpPath": "bgp_path",
    "blockClientDhcp": "block_client_dhcp",
    "blockId": "block_id",
    "blockNonIp": "block_non_ip",
    "blockPath": "block_path",
    "blockServerDhcp": "block_server_dhcp",
    "bodyConditions": "body_conditions",
    "bpduFilterEnabled": "bpdu_filter_enabled",
    "bpduFilterWhitelists": "bpdu_filter_whitelists",
    "certificateChainDepth": "certificate_chain_depth",
    "classOfService": "class_of_service",
    "clientCertificateId": "client_certificate_id",
    "clientSsl": "client_ssl",
    "closeTimeout": "close_timeout",
    "connectivityPath": "connectivity_path",
    "cookieConditions": "cookie_conditions",
    "cookieFallback": "cookie_fallback",
    "cookieGarble": "cookie_garble",
    "cookieMode": "cookie_mode",
    "cookieName": "cookie_name",
    "dataLength": "data_length",
    "defaultPoolMemberPort": "default_pool_member_port",
    "defaultPoolMemberPorts": "default_pool_member_ports",
    "defaultRule": "default_rule",
    "defaultRuleLogging": "default_rule_logging",
    "defaultRules": "default_rules",
    "defaultService": "default_service",
    "destinationNetworks": "destination_networks",
    "destinationPort": "destination_port",
    "destinationPorts": "destination_ports",
    "dhcpConfigPath": "dhcp_config_path",
    "dhcpGenericOptions": "dhcp_generic_options",
    "dhcpOption121s": "dhcp_option121s",
    "dhcpProfileId": "dhcp_profile_id",
    "dhcpRelayProfileId": "dhcp_relay_profile_id",
    "dhcpServerId": "dhcp_server_id",
    "dhcpServerIp": "dhcp_server_ip",
    "dhcpSnoopingEnabled": "dhcp_snooping_enabled",
    "discoveryProfile": "discovery_profile",
    "displayName": "display_name",
    "dnsNameServers": "dns_name_servers",
    "dnsNameservers": "dns_nameservers",
    "dnsSuffix": "dns_suffix",
    "domainName": "domain_name",
    "dscpPriority": "dscp_priority",
    "dscpTrusted": "dscp_trusted",
    "edgeClusterId": "edge_cluster_id",
    "edgeClusterMemberIndexes": "edge_cluster_member_indexes",
    "edgeClusterPath": "edge_cluster_path",
    "edgeNodePath": "edge_node_path",
    "egressQosProfilePath": "egress_qos_profile_path",
    "egressRateShaper": "egress_rate_shaper",
    "enableFirewall": "enable_firewall",
    "enablePim": "enable_pim",
    "enableRouterAdvertisement": "enable_router_advertisement",
    "enableStandbyRelocation": "enable_standby_relocation",
    "errorLogLevel": "error_log_level",
    "errorThreshold": "error_threshold",
    "etherType": "ether_type",
    "etherTypeEntries": "ether_type_entries",
    "extendedCriteria": "extended_criteria",
    "failoverMode": "failover_mode",
    "fallCount": "fall_count",
    "firewallMatch": "firewall_match",
    "firewallSections": "firewall_sections",
    "forceWhitelisting": "force_whitelisting",
    "gatewayIp": "gateway_ip",
    "gatewayPath": "gateway_path",
    "gracefulRestartMode": "graceful_restart_mode",
    "gracefulRestartStaleRouteTimer": "graceful_restart_stale_route_timer",
    "gracefulRestartTimer": "graceful_restart_timer",
    "haFlowMirroring": "ha_flow_mirroring",
    "haMode": "ha_mode",
    "haPersistenceMirroring": "ha_persistence_mirroring",
    "headerConditions": "header_conditions",
    "headerRewriteAction": "header_rewrite_action",
    "highAvailabilityMode": "high_availability_mode",
    "holdDownTime": "hold_down_time",
    "httpRedirectAction": "http_redirect_action",
    "httpRedirectTo": "http_redirect_to",
    "httpRedirectToHttps": "http_redirect_to_https",
    "httpRejectAction": "http_reject_action",
    "icmpCode": "icmp_code",
    "icmpEntries": "icmp_entries",
    "icmpType": "icmp_type",
    "idleTimeout": "idle_timeout",
    "igmpEntries": "igmp_entries",
    "ingressBroadcastRateShaper": "ingress_broadcast_rate_shaper",
    "ingressQosProfilePath": "ingress_qos_profile_path",
    "ingressRateShaper": "ingress_rate_shaper",
    "insertBefore": "insert_before",
    "insertModeParams": "insert_mode_params",
    "instanceId": "instance_id",
    "interSrIbgp": "inter_sr_ibgp",
    "internalTransitSubnets": "internal_transit_subnets",
    "intersiteConfig": "intersite_config",
    "ipAddress": "ip_address",
    "ipAddresses": "ip_addresses",
    "ipConditions": "ip_conditions",
    "ipPoolId": "ip_pool_id",
    "ipProtocolEntries": "ip_protocol_entries",
    "ipRanges": "ip_ranges",
    "ipv6DadProfilePath": "ipv6_dad_profile_path",
    "ipv6NdraProfilePath": "ipv6_ndra_profile_path",
    "isDefault": "is_default",
    "isSecure": "is_secure",
    "keepAliveTime": "keep_alive_time",
    "l2Extension": "l2_extension",
    "l4PortSetEntries": "l4_port_set_entries",
    "leaseTime": "lease_time",
    "linkedLogicalRouterPortId": "linked_logical_router_port_id",
    "linkedLogicalSwitchPortId": "linked_logical_switch_port_id",
    "localAsNum": "local_as_num",
    "localeServiceId": "locale_service_id",
    "localeServices": "locale_services",
    "logSignificantEventOnly": "log_significant_event_only",
    "logicalDhcpServerId": "logical_dhcp_server_id",
    "logicalPortTags": "logical_port_tags",
    "logicalRouterId": "logical_router_id",
    "logicalSwitchId": "logical_switch_id",
    "macAddress": "mac_address",
    "macChangeAllowed": "mac_change_allowed",
    "macLearning": "mac_learning",
    "macPoolId": "mac_pool_id",
    "matchDestinationNetwork": "match_destination_network",
    "matchSourceNetwork": "match_source_network",
    "matchStrategy": "match_strategy",
    "maxConcurrentConnections": "max_concurrent_connections",
    "maxFails": "max_fails",
    "maxNewConnectionRate": "max_new_connection_rate",
    "maximumHopLimit": "maximum_hop_limit",
    "memberGroup": "member_group",
    "membershipCriterias": "membership_criterias",
    "methodConditions": "method_conditions",
    "minActiveMembers": "min_active_members",
    "monitorPort": "monitor_port",
    "multipathRelax": "multipath_relax",
    "natPass": "nat_pass",
    "neighborAddress": "neighbor_address",
    "nextHops": "next_hops",
    "nsxId": "nsx_id",
    "overlayId": "overlay_id",
    "passiveMonitorId": "passive_monitor_id",
    "passiveMonitorPath": "passive_monitor_path",
    "persistenceProfileId": "persistence_profile_id",
    "persistenceProfilePath": "persistence_profile_path",
    "persistenceShared": "persistence_shared",
    "poolAllocation": "pool_allocation",
    "poolId": "pool_id",
    "poolPath": "pool_path",
    "preferServerCiphers": "prefer_server_ciphers",
    "preferredEdgePaths": "preferred_edge_paths",
    "purgeWhenFull": "purge_when_full",
    "qosProfile": "qos_profile",
    "rateLimits": "rate_limits",
    "redistributionConfig": "redistribution_config",
    "remoteAsNum": "remote_as_num",
    "replicationMode": "replication_mode",
    "requestBody": "request_body",
    "requestBodySize": "request_body_size",
    "requestHeaderConditions": "request_header_conditions",
    "requestHeaderSize": "request_header_size",
    "requestHeaders": "request_headers",
    "requestMethod": "request_method",
    "requestUrl": "request_url",
    "requestVersion": "request_version",
    "responseBody": "response_body",
    "responseHeaderConditions": "response_header_conditions",
    "responseStatusCodes": "response_status_codes",
    "responseTimeout": "response_timeout",
    "riseCount": "rise_count",
    "routeAdvertisementRules": "route_advertisement_rules",
    "routeAdvertisementTypes": "route_advertisement_types",
    "routeAggregations": "route_aggregations",
    "routeFilterings": "route_filterings",
    "ruleIds": "rule_ids",
    "rulePriority": "rule_priority",
    "sectionType": "section_type",
    "securityProfile": "security_profile",
    "segmentPath": "segment_path",
    "selectPoolAction": "select_pool_action",
    "sequenceNumber": "sequence_number",
    "serverAddresses": "server_addresses",
    "serverAuth": "server_auth",
    "serverAuthCaIds": "server_auth_ca_ids",
    "serverAuthCrlIds": "server_auth_crl_ids",
    "serverSsl": "server_ssl",
    "serviceBindings": "service_bindings",
    "servicePath": "service_path",
    "sessionCacheEnabled": "session_cache_enabled",
    "sessionCacheTimeout": "session_cache_timeout",
    "sitePath": "site_path",
    "snatTranslation": "snat_translation",
    "sorryPoolId": "sorry_pool_id",
    "sorryPoolPath": "sorry_pool_path",
    "sourceAddresses": "source_addresses",
    "sourceNetworks": "source_networks",
    "sourcePorts": "source_ports",
    "switchingProfileIds": "switching_profile_ids",
    "tcpConditions": "tcp_conditions",
    "tcpMultiplexingEnabled": "tcp_multiplexing_enabled",
    "tcpMultiplexingNumber": "tcp_multiplexing_number",
    "tcpStrict": "tcp_strict",
    "tier0Id": "tier0_id",
    "tier0Path": "tier0_path",
    "transitSubnets": "transit_subnets",
    "translatedNetwork": "translated_network",
    "translatedNetworks": "translated_networks",
    "translatedPorts": "translated_ports",
    "transportZoneId": "transport_zone_id",
    "transportZonePath": "transport_zone_path",
    "uriArgumentsConditions": "uri_arguments_conditions",
    "uriConditions": "uri_conditions",
    "uriRewriteAction": "uri_rewrite_action",
    "urlCategory": "url_category",
    "urpfMode": "urpf_mode",
    "versionCondition": "version_condition",
    "virtualServerIds": "virtual_server_ids",
    "vlanIds": "vlan_ids",
    "vmToolsEnabled": "vm_tools_enabled",
    "vrfConfig": "vrf_config",
    "warningThreshold": "warning_threshold",
    "xForwardedFor": "x_forwarded_for",
}
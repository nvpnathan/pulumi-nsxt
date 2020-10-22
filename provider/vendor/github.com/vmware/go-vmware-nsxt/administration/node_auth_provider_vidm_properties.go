/* Copyright © 2017 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: BSD-2-Clause

   Generated by: https://github.com/swagger-api/swagger-codegen.git */

package administration

// Node AAA provider vIDM properties
type NodeAuthProviderVidmProperties struct {

	// vIDM client id
	ClientId string `json:"client_id"`

	// vIDM client secret
	ClientSecret string `json:"client_secret,omitempty"`

	// Fully Qualified Domain Name(FQDN) of vIDM
	HostName string `json:"host_name"`

	// host name to use when creating the redirect URL for clients to follow after authenticating to vIDM
	NodeHostName string `json:"node_host_name"`

	// Hexadecimal SHA256 hash of the vIDM server's X.509 certificate
	Thumbprint string `json:"thumbprint"`

	// vIDM enable flag
	VidmEnable bool `json:"vidm_enable,omitempty"`
}
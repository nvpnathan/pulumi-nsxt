/* Copyright © 2017 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: BSD-2-Clause

   Generated by: https://github.com/swagger-api/swagger-codegen.git */

package administration

type SuccessNodeSupportBundleResult struct {

	// Name of support bundle, e.g. nsx_NODETYPE_UUID_YYYYMMDD_HHMMSS.tgz
	BundleName string `json:"bundle_name,omitempty"`

	// Display name of node
	NodeDisplayName string `json:"node_display_name,omitempty"`

	// UUID of node
	NodeId string `json:"node_id,omitempty"`

	// File's SHA256 thumbprint
	Sha256Thumbprint string `json:"sha256_thumbprint,omitempty"`
}

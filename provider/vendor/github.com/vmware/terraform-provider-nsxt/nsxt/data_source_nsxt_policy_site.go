/* Copyright © 2019 VMware, Inc. All Rights Reserved.
   SPDX-License-Identifier: MPL-2.0 */

package nsxt

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func dataSourceNsxtPolicySite() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceNsxtPolicySiteRead,

		Schema: map[string]*schema.Schema{
			"id":           getDataSourceIDSchema(),
			"display_name": getDataSourceDisplayNameSchema(),
			"description":  getDataSourceDescriptionSchema(),
			"path":         getPathSchema(),
		},
	}
}

func dataSourceNsxtPolicySiteRead(d *schema.ResourceData, m interface{}) error {
	if !isPolicyGlobalManager(m) {
		return globalManagerOnlyError()
	}

	_, err := policyDataSourceResourceRead(d, getPolicyConnector(m), "Site", nil)
	if err != nil {
		return err
	}

	return nil
}

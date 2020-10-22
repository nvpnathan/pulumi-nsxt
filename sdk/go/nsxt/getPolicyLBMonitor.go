// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetPolicyLBMonitor(ctx *pulumi.Context, args *GetPolicyLBMonitorArgs, opts ...pulumi.InvokeOption) (*GetPolicyLBMonitorResult, error) {
	var rv GetPolicyLBMonitorResult
	err := ctx.Invoke("nsxt:index/getPolicyLBMonitor:getPolicyLBMonitor", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyLBMonitor.
type GetPolicyLBMonitorArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
	Type        *string `pulumi:"type"`
}

// A collection of values returned by getPolicyLBMonitor.
type GetPolicyLBMonitorResult struct {
	Description string  `pulumi:"description"`
	DisplayName string  `pulumi:"displayName"`
	Id          string  `pulumi:"id"`
	Path        string  `pulumi:"path"`
	Type        *string `pulumi:"type"`
}

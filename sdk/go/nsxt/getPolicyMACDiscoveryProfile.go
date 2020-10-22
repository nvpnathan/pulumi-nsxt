// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetPolicyMACDiscoveryProfile(ctx *pulumi.Context, args *GetPolicyMACDiscoveryProfileArgs, opts ...pulumi.InvokeOption) (*GetPolicyMACDiscoveryProfileResult, error) {
	var rv GetPolicyMACDiscoveryProfileResult
	err := ctx.Invoke("nsxt:index/getPolicyMACDiscoveryProfile:getPolicyMACDiscoveryProfile", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyMACDiscoveryProfile.
type GetPolicyMACDiscoveryProfileArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getPolicyMACDiscoveryProfile.
type GetPolicyMACDiscoveryProfileResult struct {
	Description string `pulumi:"description"`
	DisplayName string `pulumi:"displayName"`
	Id          string `pulumi:"id"`
	Path        string `pulumi:"path"`
}

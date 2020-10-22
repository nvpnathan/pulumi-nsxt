// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetPolicyLBAppProfile(ctx *pulumi.Context, args *GetPolicyLBAppProfileArgs, opts ...pulumi.InvokeOption) (*GetPolicyLBAppProfileResult, error) {
	var rv GetPolicyLBAppProfileResult
	err := ctx.Invoke("nsxt:index/getPolicyLBAppProfile:getPolicyLBAppProfile", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyLBAppProfile.
type GetPolicyLBAppProfileArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
	Type        *string `pulumi:"type"`
}

// A collection of values returned by getPolicyLBAppProfile.
type GetPolicyLBAppProfileResult struct {
	Description string  `pulumi:"description"`
	DisplayName string  `pulumi:"displayName"`
	Id          string  `pulumi:"id"`
	Path        string  `pulumi:"path"`
	Type        *string `pulumi:"type"`
}
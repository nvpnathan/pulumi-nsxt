// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetPolicyGatewayQOSProfile(ctx *pulumi.Context, args *GetPolicyGatewayQOSProfileArgs, opts ...pulumi.InvokeOption) (*GetPolicyGatewayQOSProfileResult, error) {
	var rv GetPolicyGatewayQOSProfileResult
	err := ctx.Invoke("nsxt:index/getPolicyGatewayQOSProfile:getPolicyGatewayQOSProfile", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyGatewayQOSProfile.
type GetPolicyGatewayQOSProfileArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getPolicyGatewayQOSProfile.
type GetPolicyGatewayQOSProfileResult struct {
	Description string `pulumi:"description"`
	DisplayName string `pulumi:"displayName"`
	Id          string `pulumi:"id"`
	Path        string `pulumi:"path"`
}

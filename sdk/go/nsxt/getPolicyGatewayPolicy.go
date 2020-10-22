// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func LookupPolicyGatewayPolicy(ctx *pulumi.Context, args *LookupPolicyGatewayPolicyArgs, opts ...pulumi.InvokeOption) (*LookupPolicyGatewayPolicyResult, error) {
	var rv LookupPolicyGatewayPolicyResult
	err := ctx.Invoke("nsxt:index/getPolicyGatewayPolicy:getPolicyGatewayPolicy", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyGatewayPolicy.
type LookupPolicyGatewayPolicyArgs struct {
	Category    *string `pulumi:"category"`
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Domain      *string `pulumi:"domain"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getPolicyGatewayPolicy.
type LookupPolicyGatewayPolicyResult struct {
	Category    string  `pulumi:"category"`
	Description string  `pulumi:"description"`
	DisplayName string  `pulumi:"displayName"`
	Domain      *string `pulumi:"domain"`
	Id          string  `pulumi:"id"`
	Path        string  `pulumi:"path"`
}

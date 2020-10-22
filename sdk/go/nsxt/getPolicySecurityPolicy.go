// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func LookupPolicySecurityPolicy(ctx *pulumi.Context, args *LookupPolicySecurityPolicyArgs, opts ...pulumi.InvokeOption) (*LookupPolicySecurityPolicyResult, error) {
	var rv LookupPolicySecurityPolicyResult
	err := ctx.Invoke("nsxt:index/getPolicySecurityPolicy:getPolicySecurityPolicy", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicySecurityPolicy.
type LookupPolicySecurityPolicyArgs struct {
	Category    *string `pulumi:"category"`
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Domain      *string `pulumi:"domain"`
	Id          *string `pulumi:"id"`
	IsDefault   *bool   `pulumi:"isDefault"`
}

// A collection of values returned by getPolicySecurityPolicy.
type LookupPolicySecurityPolicyResult struct {
	Category    string  `pulumi:"category"`
	Description string  `pulumi:"description"`
	DisplayName string  `pulumi:"displayName"`
	Domain      *string `pulumi:"domain"`
	Id          string  `pulumi:"id"`
	IsDefault   *bool   `pulumi:"isDefault"`
	Path        string  `pulumi:"path"`
}

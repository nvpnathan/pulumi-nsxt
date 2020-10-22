// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func LookupPolicyService(ctx *pulumi.Context, args *LookupPolicyServiceArgs, opts ...pulumi.InvokeOption) (*LookupPolicyServiceResult, error) {
	var rv LookupPolicyServiceResult
	err := ctx.Invoke("nsxt:index/getPolicyService:getPolicyService", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyService.
type LookupPolicyServiceArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getPolicyService.
type LookupPolicyServiceResult struct {
	Description string `pulumi:"description"`
	DisplayName string `pulumi:"displayName"`
	Id          string `pulumi:"id"`
	Path        string `pulumi:"path"`
}

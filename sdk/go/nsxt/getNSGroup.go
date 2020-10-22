// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetNSGroup(ctx *pulumi.Context, args *GetNSGroupArgs, opts ...pulumi.InvokeOption) (*GetNSGroupResult, error) {
	var rv GetNSGroupResult
	err := ctx.Invoke("nsxt:index/getNSGroup:getNSGroup", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNSGroup.
type GetNSGroupArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getNSGroup.
type GetNSGroupResult struct {
	Description string `pulumi:"description"`
	DisplayName string `pulumi:"displayName"`
	Id          string `pulumi:"id"`
}

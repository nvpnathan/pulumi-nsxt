// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetMACPool(ctx *pulumi.Context, args *GetMACPoolArgs, opts ...pulumi.InvokeOption) (*GetMACPoolResult, error) {
	var rv GetMACPoolResult
	err := ctx.Invoke("nsxt:index/getMACPool:getMACPool", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMACPool.
type GetMACPoolArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getMACPool.
type GetMACPoolResult struct {
	Description string `pulumi:"description"`
	DisplayName string `pulumi:"displayName"`
	Id          string `pulumi:"id"`
}

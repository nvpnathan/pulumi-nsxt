// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetNSService(ctx *pulumi.Context, args *GetNSServiceArgs, opts ...pulumi.InvokeOption) (*GetNSServiceResult, error) {
	var rv GetNSServiceResult
	err := ctx.Invoke("nsxt:index/getNSService:getNSService", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getNSService.
type GetNSServiceArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getNSService.
type GetNSServiceResult struct {
	Description string `pulumi:"description"`
	DisplayName string `pulumi:"displayName"`
	Id          string `pulumi:"id"`
}

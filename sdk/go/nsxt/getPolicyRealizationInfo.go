// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetPolicyRealizationInfo(ctx *pulumi.Context, args *GetPolicyRealizationInfoArgs, opts ...pulumi.InvokeOption) (*GetPolicyRealizationInfoResult, error) {
	var rv GetPolicyRealizationInfoResult
	err := ctx.Invoke("nsxt:index/getPolicyRealizationInfo:getPolicyRealizationInfo", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyRealizationInfo.
type GetPolicyRealizationInfoArgs struct {
	EntityType *string `pulumi:"entityType"`
	Id         *string `pulumi:"id"`
	Path       string  `pulumi:"path"`
	SitePath   *string `pulumi:"sitePath"`
}

// A collection of values returned by getPolicyRealizationInfo.
type GetPolicyRealizationInfoResult struct {
	EntityType string  `pulumi:"entityType"`
	Id         string  `pulumi:"id"`
	Path       string  `pulumi:"path"`
	RealizedId string  `pulumi:"realizedId"`
	SitePath   *string `pulumi:"sitePath"`
	State      string  `pulumi:"state"`
}

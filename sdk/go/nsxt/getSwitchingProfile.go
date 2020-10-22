// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetSwitchingProfile(ctx *pulumi.Context, args *GetSwitchingProfileArgs, opts ...pulumi.InvokeOption) (*GetSwitchingProfileResult, error) {
	var rv GetSwitchingProfileResult
	err := ctx.Invoke("nsxt:index/getSwitchingProfile:getSwitchingProfile", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSwitchingProfile.
type GetSwitchingProfileArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getSwitchingProfile.
type GetSwitchingProfileResult struct {
	Description  string `pulumi:"description"`
	DisplayName  string `pulumi:"displayName"`
	Id           string `pulumi:"id"`
	ResourceType string `pulumi:"resourceType"`
}

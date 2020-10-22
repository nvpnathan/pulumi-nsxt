// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetPolicyEdgeNode(ctx *pulumi.Context, args *GetPolicyEdgeNodeArgs, opts ...pulumi.InvokeOption) (*GetPolicyEdgeNodeResult, error) {
	var rv GetPolicyEdgeNodeResult
	err := ctx.Invoke("nsxt:index/getPolicyEdgeNode:getPolicyEdgeNode", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getPolicyEdgeNode.
type GetPolicyEdgeNodeArgs struct {
	Description     *string `pulumi:"description"`
	DisplayName     *string `pulumi:"displayName"`
	EdgeClusterPath string  `pulumi:"edgeClusterPath"`
	Id              *string `pulumi:"id"`
	MemberIndex     *int    `pulumi:"memberIndex"`
}

// A collection of values returned by getPolicyEdgeNode.
type GetPolicyEdgeNodeResult struct {
	Description     string `pulumi:"description"`
	DisplayName     string `pulumi:"displayName"`
	EdgeClusterPath string `pulumi:"edgeClusterPath"`
	Id              string `pulumi:"id"`
	MemberIndex     *int   `pulumi:"memberIndex"`
	Path            string `pulumi:"path"`
}
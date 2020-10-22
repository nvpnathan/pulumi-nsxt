// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyVMTags struct {
	pulumi.CustomResourceState

	// Instance id
	InstanceId pulumi.StringOutput `pulumi:"instanceId"`
	// Tag specificiation for corresponding segment port
	Ports PolicyVMTagsPortArrayOutput `pulumi:"ports"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyVMTagsTagArrayOutput `pulumi:"tags"`
}

// NewPolicyVMTags registers a new resource with the given unique name, arguments, and options.
func NewPolicyVMTags(ctx *pulumi.Context,
	name string, args *PolicyVMTagsArgs, opts ...pulumi.ResourceOption) (*PolicyVMTags, error) {
	if args == nil || args.InstanceId == nil {
		return nil, errors.New("missing required argument 'InstanceId'")
	}
	if args == nil {
		args = &PolicyVMTagsArgs{}
	}
	var resource PolicyVMTags
	err := ctx.RegisterResource("nsxt:index/policyVMTags:PolicyVMTags", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyVMTags gets an existing PolicyVMTags resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyVMTags(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyVMTagsState, opts ...pulumi.ResourceOption) (*PolicyVMTags, error) {
	var resource PolicyVMTags
	err := ctx.ReadResource("nsxt:index/policyVMTags:PolicyVMTags", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyVMTags resources.
type policyVMTagsState struct {
	// Instance id
	InstanceId *string `pulumi:"instanceId"`
	// Tag specificiation for corresponding segment port
	Ports []PolicyVMTagsPort `pulumi:"ports"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyVMTagsTag `pulumi:"tags"`
}

type PolicyVMTagsState struct {
	// Instance id
	InstanceId pulumi.StringPtrInput
	// Tag specificiation for corresponding segment port
	Ports PolicyVMTagsPortArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyVMTagsTagArrayInput
}

func (PolicyVMTagsState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyVMTagsState)(nil)).Elem()
}

type policyVMTagsArgs struct {
	// Instance id
	InstanceId string `pulumi:"instanceId"`
	// Tag specificiation for corresponding segment port
	Ports []PolicyVMTagsPort `pulumi:"ports"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyVMTagsTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyVMTags resource.
type PolicyVMTagsArgs struct {
	// Instance id
	InstanceId pulumi.StringInput
	// Tag specificiation for corresponding segment port
	Ports PolicyVMTagsPortArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyVMTagsTagArrayInput
}

func (PolicyVMTagsArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyVMTagsArgs)(nil)).Elem()
}

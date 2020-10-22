// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type IPPoolAllocationIPAddress struct {
	pulumi.CustomResourceState

	// IP Address that is allocated from the pool
	AllocationId pulumi.StringOutput `pulumi:"allocationId"`
	// ID of IP pool that allocation belongs to
	IpPoolId pulumi.StringOutput `pulumi:"ipPoolId"`
}

// NewIPPoolAllocationIPAddress registers a new resource with the given unique name, arguments, and options.
func NewIPPoolAllocationIPAddress(ctx *pulumi.Context,
	name string, args *IPPoolAllocationIPAddressArgs, opts ...pulumi.ResourceOption) (*IPPoolAllocationIPAddress, error) {
	if args == nil || args.IpPoolId == nil {
		return nil, errors.New("missing required argument 'IpPoolId'")
	}
	if args == nil {
		args = &IPPoolAllocationIPAddressArgs{}
	}
	var resource IPPoolAllocationIPAddress
	err := ctx.RegisterResource("nsxt:index/iPPoolAllocationIPAddress:IPPoolAllocationIPAddress", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetIPPoolAllocationIPAddress gets an existing IPPoolAllocationIPAddress resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetIPPoolAllocationIPAddress(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *IPPoolAllocationIPAddressState, opts ...pulumi.ResourceOption) (*IPPoolAllocationIPAddress, error) {
	var resource IPPoolAllocationIPAddress
	err := ctx.ReadResource("nsxt:index/iPPoolAllocationIPAddress:IPPoolAllocationIPAddress", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering IPPoolAllocationIPAddress resources.
type ippoolAllocationIPAddressState struct {
	// IP Address that is allocated from the pool
	AllocationId *string `pulumi:"allocationId"`
	// ID of IP pool that allocation belongs to
	IpPoolId *string `pulumi:"ipPoolId"`
}

type IPPoolAllocationIPAddressState struct {
	// IP Address that is allocated from the pool
	AllocationId pulumi.StringPtrInput
	// ID of IP pool that allocation belongs to
	IpPoolId pulumi.StringPtrInput
}

func (IPPoolAllocationIPAddressState) ElementType() reflect.Type {
	return reflect.TypeOf((*ippoolAllocationIPAddressState)(nil)).Elem()
}

type ippoolAllocationIPAddressArgs struct {
	// IP Address that is allocated from the pool
	AllocationId *string `pulumi:"allocationId"`
	// ID of IP pool that allocation belongs to
	IpPoolId string `pulumi:"ipPoolId"`
}

// The set of arguments for constructing a IPPoolAllocationIPAddress resource.
type IPPoolAllocationIPAddressArgs struct {
	// IP Address that is allocated from the pool
	AllocationId pulumi.StringPtrInput
	// ID of IP pool that allocation belongs to
	IpPoolId pulumi.StringInput
}

func (IPPoolAllocationIPAddressArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ippoolAllocationIPAddressArgs)(nil)).Elem()
}

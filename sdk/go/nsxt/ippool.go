// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type IPPool struct {
	pulumi.CustomResourceState

	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// List of IPv4 subnets
	Subnets IPPoolSubnetArrayOutput `pulumi:"subnets"`
	// Set of opaque identifiers meaningful to the user
	Tags IPPoolTagArrayOutput `pulumi:"tags"`
}

// NewIPPool registers a new resource with the given unique name, arguments, and options.
func NewIPPool(ctx *pulumi.Context,
	name string, args *IPPoolArgs, opts ...pulumi.ResourceOption) (*IPPool, error) {
	if args == nil {
		args = &IPPoolArgs{}
	}
	var resource IPPool
	err := ctx.RegisterResource("nsxt:index/iPPool:IPPool", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetIPPool gets an existing IPPool resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetIPPool(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *IPPoolState, opts ...pulumi.ResourceOption) (*IPPool, error) {
	var resource IPPool
	err := ctx.ReadResource("nsxt:index/iPPool:IPPool", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering IPPool resources.
type ippoolState struct {
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// List of IPv4 subnets
	Subnets []IPPoolSubnet `pulumi:"subnets"`
	// Set of opaque identifiers meaningful to the user
	Tags []IPPoolTag `pulumi:"tags"`
}

type IPPoolState struct {
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// List of IPv4 subnets
	Subnets IPPoolSubnetArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags IPPoolTagArrayInput
}

func (IPPoolState) ElementType() reflect.Type {
	return reflect.TypeOf((*ippoolState)(nil)).Elem()
}

type ippoolArgs struct {
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// List of IPv4 subnets
	Subnets []IPPoolSubnet `pulumi:"subnets"`
	// Set of opaque identifiers meaningful to the user
	Tags []IPPoolTag `pulumi:"tags"`
}

// The set of arguments for constructing a IPPool resource.
type IPPoolArgs struct {
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// List of IPv4 subnets
	Subnets IPPoolSubnetArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags IPPoolTagArrayInput
}

func (IPPoolArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ippoolArgs)(nil)).Elem()
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyIPAddressAllocation struct {
	pulumi.CustomResourceState

	// The IP allocated. If unspecified any free IP will be allocated.
	AllocationIp pulumi.StringOutput `pulumi:"allocationIp"`
	// Description for this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// Display name for this resource
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId pulumi.StringOutput `pulumi:"nsxId"`
	// Policy path for this resource
	Path pulumi.StringOutput `pulumi:"path"`
	// The path of the IP Pool for this allocation
	PoolPath pulumi.StringOutput `pulumi:"poolPath"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyIPAddressAllocationTagArrayOutput `pulumi:"tags"`
}

// NewPolicyIPAddressAllocation registers a new resource with the given unique name, arguments, and options.
func NewPolicyIPAddressAllocation(ctx *pulumi.Context,
	name string, args *PolicyIPAddressAllocationArgs, opts ...pulumi.ResourceOption) (*PolicyIPAddressAllocation, error) {
	if args == nil || args.DisplayName == nil {
		return nil, errors.New("missing required argument 'DisplayName'")
	}
	if args == nil || args.PoolPath == nil {
		return nil, errors.New("missing required argument 'PoolPath'")
	}
	if args == nil {
		args = &PolicyIPAddressAllocationArgs{}
	}
	var resource PolicyIPAddressAllocation
	err := ctx.RegisterResource("nsxt:index/policyIPAddressAllocation:PolicyIPAddressAllocation", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyIPAddressAllocation gets an existing PolicyIPAddressAllocation resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyIPAddressAllocation(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyIPAddressAllocationState, opts ...pulumi.ResourceOption) (*PolicyIPAddressAllocation, error) {
	var resource PolicyIPAddressAllocation
	err := ctx.ReadResource("nsxt:index/policyIPAddressAllocation:PolicyIPAddressAllocation", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyIPAddressAllocation resources.
type policyIPAddressAllocationState struct {
	// The IP allocated. If unspecified any free IP will be allocated.
	AllocationIp *string `pulumi:"allocationIp"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName *string `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path for this resource
	Path *string `pulumi:"path"`
	// The path of the IP Pool for this allocation
	PoolPath *string `pulumi:"poolPath"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyIPAddressAllocationTag `pulumi:"tags"`
}

type PolicyIPAddressAllocationState struct {
	// The IP allocated. If unspecified any free IP will be allocated.
	AllocationIp pulumi.StringPtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringPtrInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path for this resource
	Path pulumi.StringPtrInput
	// The path of the IP Pool for this allocation
	PoolPath pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyIPAddressAllocationTagArrayInput
}

func (PolicyIPAddressAllocationState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyIPAddressAllocationState)(nil)).Elem()
}

type policyIPAddressAllocationArgs struct {
	// The IP allocated. If unspecified any free IP will be allocated.
	AllocationIp *string `pulumi:"allocationIp"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName string `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// The path of the IP Pool for this allocation
	PoolPath string `pulumi:"poolPath"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyIPAddressAllocationTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyIPAddressAllocation resource.
type PolicyIPAddressAllocationArgs struct {
	// The IP allocated. If unspecified any free IP will be allocated.
	AllocationIp pulumi.StringPtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// The path of the IP Pool for this allocation
	PoolPath pulumi.StringInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyIPAddressAllocationTagArrayInput
}

func (PolicyIPAddressAllocationArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyIPAddressAllocationArgs)(nil)).Elem()
}

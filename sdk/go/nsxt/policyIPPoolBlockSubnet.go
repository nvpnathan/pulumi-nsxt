// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyIPPoolBlockSubnet struct {
	pulumi.CustomResourceState

	// If true, the first IP in the range will be reserved for gateway
	AutoAssignGateway pulumi.BoolPtrOutput `pulumi:"autoAssignGateway"`
	// Policy path to the IP Block
	BlockPath pulumi.StringOutput `pulumi:"blockPath"`
	// Description for this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// Display name for this resource
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId pulumi.StringOutput `pulumi:"nsxId"`
	// Policy path for this resource
	Path pulumi.StringOutput `pulumi:"path"`
	// Policy path to the IP Pool for this Subnet
	PoolPath pulumi.StringOutput `pulumi:"poolPath"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Number of addresses
	Size pulumi.IntOutput `pulumi:"size"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyIPPoolBlockSubnetTagArrayOutput `pulumi:"tags"`
}

// NewPolicyIPPoolBlockSubnet registers a new resource with the given unique name, arguments, and options.
func NewPolicyIPPoolBlockSubnet(ctx *pulumi.Context,
	name string, args *PolicyIPPoolBlockSubnetArgs, opts ...pulumi.ResourceOption) (*PolicyIPPoolBlockSubnet, error) {
	if args == nil || args.BlockPath == nil {
		return nil, errors.New("missing required argument 'BlockPath'")
	}
	if args == nil || args.DisplayName == nil {
		return nil, errors.New("missing required argument 'DisplayName'")
	}
	if args == nil || args.PoolPath == nil {
		return nil, errors.New("missing required argument 'PoolPath'")
	}
	if args == nil || args.Size == nil {
		return nil, errors.New("missing required argument 'Size'")
	}
	if args == nil {
		args = &PolicyIPPoolBlockSubnetArgs{}
	}
	var resource PolicyIPPoolBlockSubnet
	err := ctx.RegisterResource("nsxt:index/policyIPPoolBlockSubnet:PolicyIPPoolBlockSubnet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyIPPoolBlockSubnet gets an existing PolicyIPPoolBlockSubnet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyIPPoolBlockSubnet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyIPPoolBlockSubnetState, opts ...pulumi.ResourceOption) (*PolicyIPPoolBlockSubnet, error) {
	var resource PolicyIPPoolBlockSubnet
	err := ctx.ReadResource("nsxt:index/policyIPPoolBlockSubnet:PolicyIPPoolBlockSubnet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyIPPoolBlockSubnet resources.
type policyIPPoolBlockSubnetState struct {
	// If true, the first IP in the range will be reserved for gateway
	AutoAssignGateway *bool `pulumi:"autoAssignGateway"`
	// Policy path to the IP Block
	BlockPath *string `pulumi:"blockPath"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName *string `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path for this resource
	Path *string `pulumi:"path"`
	// Policy path to the IP Pool for this Subnet
	PoolPath *string `pulumi:"poolPath"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Number of addresses
	Size *int `pulumi:"size"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyIPPoolBlockSubnetTag `pulumi:"tags"`
}

type PolicyIPPoolBlockSubnetState struct {
	// If true, the first IP in the range will be reserved for gateway
	AutoAssignGateway pulumi.BoolPtrInput
	// Policy path to the IP Block
	BlockPath pulumi.StringPtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringPtrInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path for this resource
	Path pulumi.StringPtrInput
	// Policy path to the IP Pool for this Subnet
	PoolPath pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Number of addresses
	Size pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyIPPoolBlockSubnetTagArrayInput
}

func (PolicyIPPoolBlockSubnetState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyIPPoolBlockSubnetState)(nil)).Elem()
}

type policyIPPoolBlockSubnetArgs struct {
	// If true, the first IP in the range will be reserved for gateway
	AutoAssignGateway *bool `pulumi:"autoAssignGateway"`
	// Policy path to the IP Block
	BlockPath string `pulumi:"blockPath"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName string `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path to the IP Pool for this Subnet
	PoolPath string `pulumi:"poolPath"`
	// Number of addresses
	Size int `pulumi:"size"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyIPPoolBlockSubnetTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyIPPoolBlockSubnet resource.
type PolicyIPPoolBlockSubnetArgs struct {
	// If true, the first IP in the range will be reserved for gateway
	AutoAssignGateway pulumi.BoolPtrInput
	// Policy path to the IP Block
	BlockPath pulumi.StringInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path to the IP Pool for this Subnet
	PoolPath pulumi.StringInput
	// Number of addresses
	Size pulumi.IntInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyIPPoolBlockSubnetTagArrayInput
}

func (PolicyIPPoolBlockSubnetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyIPPoolBlockSubnetArgs)(nil)).Elem()
}
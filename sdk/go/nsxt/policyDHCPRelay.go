// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyDHCPRelay struct {
	pulumi.CustomResourceState

	// Description for this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// Display name for this resource
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId pulumi.StringOutput `pulumi:"nsxId"`
	// Policy path for this resource
	Path pulumi.StringOutput `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision        pulumi.IntOutput         `pulumi:"revision"`
	ServerAddresses pulumi.StringArrayOutput `pulumi:"serverAddresses"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyDHCPRelayTagArrayOutput `pulumi:"tags"`
}

// NewPolicyDHCPRelay registers a new resource with the given unique name, arguments, and options.
func NewPolicyDHCPRelay(ctx *pulumi.Context,
	name string, args *PolicyDHCPRelayArgs, opts ...pulumi.ResourceOption) (*PolicyDHCPRelay, error) {
	if args == nil || args.DisplayName == nil {
		return nil, errors.New("missing required argument 'DisplayName'")
	}
	if args == nil || args.ServerAddresses == nil {
		return nil, errors.New("missing required argument 'ServerAddresses'")
	}
	if args == nil {
		args = &PolicyDHCPRelayArgs{}
	}
	var resource PolicyDHCPRelay
	err := ctx.RegisterResource("nsxt:index/policyDHCPRelay:PolicyDHCPRelay", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyDHCPRelay gets an existing PolicyDHCPRelay resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyDHCPRelay(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyDHCPRelayState, opts ...pulumi.ResourceOption) (*PolicyDHCPRelay, error) {
	var resource PolicyDHCPRelay
	err := ctx.ReadResource("nsxt:index/policyDHCPRelay:PolicyDHCPRelay", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyDHCPRelay resources.
type policyDHCPRelayState struct {
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName *string `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path for this resource
	Path *string `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision        *int     `pulumi:"revision"`
	ServerAddresses []string `pulumi:"serverAddresses"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyDHCPRelayTag `pulumi:"tags"`
}

type PolicyDHCPRelayState struct {
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringPtrInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path for this resource
	Path pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision        pulumi.IntPtrInput
	ServerAddresses pulumi.StringArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyDHCPRelayTagArrayInput
}

func (PolicyDHCPRelayState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyDHCPRelayState)(nil)).Elem()
}

type policyDHCPRelayArgs struct {
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName string `pulumi:"displayName"`
	// NSX ID for this resource
	NsxId           *string  `pulumi:"nsxId"`
	ServerAddresses []string `pulumi:"serverAddresses"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyDHCPRelayTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyDHCPRelay resource.
type PolicyDHCPRelayArgs struct {
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringInput
	// NSX ID for this resource
	NsxId           pulumi.StringPtrInput
	ServerAddresses pulumi.StringArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyDHCPRelayTagArrayInput
}

func (PolicyDHCPRelayArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyDHCPRelayArgs)(nil)).Elem()
}

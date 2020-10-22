// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type LBPassiveMonitor struct {
	pulumi.CustomResourceState

	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
	// period
	MaxFails pulumi.IntPtrOutput `pulumi:"maxFails"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags LBPassiveMonitorTagArrayOutput `pulumi:"tags"`
	// After this timeout period, the member is tried again for a new connection to see if it is available
	Timeout pulumi.IntPtrOutput `pulumi:"timeout"`
}

// NewLBPassiveMonitor registers a new resource with the given unique name, arguments, and options.
func NewLBPassiveMonitor(ctx *pulumi.Context,
	name string, args *LBPassiveMonitorArgs, opts ...pulumi.ResourceOption) (*LBPassiveMonitor, error) {
	if args == nil {
		args = &LBPassiveMonitorArgs{}
	}
	var resource LBPassiveMonitor
	err := ctx.RegisterResource("nsxt:index/lBPassiveMonitor:LBPassiveMonitor", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLBPassiveMonitor gets an existing LBPassiveMonitor resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLBPassiveMonitor(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LBPassiveMonitorState, opts ...pulumi.ResourceOption) (*LBPassiveMonitor, error) {
	var resource LBPassiveMonitor
	err := ctx.ReadResource("nsxt:index/lBPassiveMonitor:LBPassiveMonitor", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LBPassiveMonitor resources.
type lbpassiveMonitorState struct {
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
	// period
	MaxFails *int `pulumi:"maxFails"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBPassiveMonitorTag `pulumi:"tags"`
	// After this timeout period, the member is tried again for a new connection to see if it is available
	Timeout *int `pulumi:"timeout"`
}

type LBPassiveMonitorState struct {
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
	// period
	MaxFails pulumi.IntPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBPassiveMonitorTagArrayInput
	// After this timeout period, the member is tried again for a new connection to see if it is available
	Timeout pulumi.IntPtrInput
}

func (LBPassiveMonitorState) ElementType() reflect.Type {
	return reflect.TypeOf((*lbpassiveMonitorState)(nil)).Elem()
}

type lbpassiveMonitorArgs struct {
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
	// period
	MaxFails *int `pulumi:"maxFails"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBPassiveMonitorTag `pulumi:"tags"`
	// After this timeout period, the member is tried again for a new connection to see if it is available
	Timeout *int `pulumi:"timeout"`
}

// The set of arguments for constructing a LBPassiveMonitor resource.
type LBPassiveMonitorArgs struct {
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
	// period
	MaxFails pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBPassiveMonitorTagArrayInput
	// After this timeout period, the member is tried again for a new connection to see if it is available
	Timeout pulumi.IntPtrInput
}

func (LBPassiveMonitorArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*lbpassiveMonitorArgs)(nil)).Elem()
}

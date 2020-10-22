// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type LBPool struct {
	pulumi.CustomResourceState

	// Active health monitor Id. If one is not set, the active healthchecks will be disabled
	ActiveMonitorId pulumi.StringPtrOutput `pulumi:"activeMonitorId"`
	// Load balancing algorithm controls how the incoming connections are distributed among the members
	Algorithm pulumi.StringPtrOutput `pulumi:"algorithm"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
	MemberGroup LBPoolMemberGroupPtrOutput `pulumi:"memberGroup"`
	// List of server pool members. Each pool member is identified, typically, by an IP address and a port
	Members LBPoolMemberArrayOutput `pulumi:"members"`
	// The minimum number of members for the pool to be considered active
	MinActiveMembers pulumi.IntPtrOutput `pulumi:"minActiveMembers"`
	// Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
	PassiveMonitorId pulumi.StringPtrOutput `pulumi:"passiveMonitorId"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// SNAT translation configuration
	SnatTranslation LBPoolSnatTranslationOutput `pulumi:"snatTranslation"`
	// Set of opaque identifiers meaningful to the user
	Tags LBPoolTagArrayOutput `pulumi:"tags"`
	// TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
	// multiple client requests from different client TCP connections
	TcpMultiplexingEnabled pulumi.BoolPtrOutput `pulumi:"tcpMultiplexingEnabled"`
	// The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
	TcpMultiplexingNumber pulumi.IntPtrOutput `pulumi:"tcpMultiplexingNumber"`
}

// NewLBPool registers a new resource with the given unique name, arguments, and options.
func NewLBPool(ctx *pulumi.Context,
	name string, args *LBPoolArgs, opts ...pulumi.ResourceOption) (*LBPool, error) {
	if args == nil {
		args = &LBPoolArgs{}
	}
	var resource LBPool
	err := ctx.RegisterResource("nsxt:index/lBPool:LBPool", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLBPool gets an existing LBPool resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLBPool(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LBPoolState, opts ...pulumi.ResourceOption) (*LBPool, error) {
	var resource LBPool
	err := ctx.ReadResource("nsxt:index/lBPool:LBPool", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LBPool resources.
type lbpoolState struct {
	// Active health monitor Id. If one is not set, the active healthchecks will be disabled
	ActiveMonitorId *string `pulumi:"activeMonitorId"`
	// Load balancing algorithm controls how the incoming connections are distributed among the members
	Algorithm *string `pulumi:"algorithm"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
	MemberGroup *LBPoolMemberGroup `pulumi:"memberGroup"`
	// List of server pool members. Each pool member is identified, typically, by an IP address and a port
	Members []LBPoolMember `pulumi:"members"`
	// The minimum number of members for the pool to be considered active
	MinActiveMembers *int `pulumi:"minActiveMembers"`
	// Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
	PassiveMonitorId *string `pulumi:"passiveMonitorId"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// SNAT translation configuration
	SnatTranslation *LBPoolSnatTranslation `pulumi:"snatTranslation"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBPoolTag `pulumi:"tags"`
	// TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
	// multiple client requests from different client TCP connections
	TcpMultiplexingEnabled *bool `pulumi:"tcpMultiplexingEnabled"`
	// The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
	TcpMultiplexingNumber *int `pulumi:"tcpMultiplexingNumber"`
}

type LBPoolState struct {
	// Active health monitor Id. If one is not set, the active healthchecks will be disabled
	ActiveMonitorId pulumi.StringPtrInput
	// Load balancing algorithm controls how the incoming connections are distributed among the members
	Algorithm pulumi.StringPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
	MemberGroup LBPoolMemberGroupPtrInput
	// List of server pool members. Each pool member is identified, typically, by an IP address and a port
	Members LBPoolMemberArrayInput
	// The minimum number of members for the pool to be considered active
	MinActiveMembers pulumi.IntPtrInput
	// Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
	PassiveMonitorId pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// SNAT translation configuration
	SnatTranslation LBPoolSnatTranslationPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBPoolTagArrayInput
	// TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
	// multiple client requests from different client TCP connections
	TcpMultiplexingEnabled pulumi.BoolPtrInput
	// The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
	TcpMultiplexingNumber pulumi.IntPtrInput
}

func (LBPoolState) ElementType() reflect.Type {
	return reflect.TypeOf((*lbpoolState)(nil)).Elem()
}

type lbpoolArgs struct {
	// Active health monitor Id. If one is not set, the active healthchecks will be disabled
	ActiveMonitorId *string `pulumi:"activeMonitorId"`
	// Load balancing algorithm controls how the incoming connections are distributed among the members
	Algorithm *string `pulumi:"algorithm"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
	MemberGroup *LBPoolMemberGroup `pulumi:"memberGroup"`
	// List of server pool members. Each pool member is identified, typically, by an IP address and a port
	Members []LBPoolMember `pulumi:"members"`
	// The minimum number of members for the pool to be considered active
	MinActiveMembers *int `pulumi:"minActiveMembers"`
	// Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
	PassiveMonitorId *string `pulumi:"passiveMonitorId"`
	// SNAT translation configuration
	SnatTranslation *LBPoolSnatTranslation `pulumi:"snatTranslation"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBPoolTag `pulumi:"tags"`
	// TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
	// multiple client requests from different client TCP connections
	TcpMultiplexingEnabled *bool `pulumi:"tcpMultiplexingEnabled"`
	// The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
	TcpMultiplexingNumber *int `pulumi:"tcpMultiplexingNumber"`
}

// The set of arguments for constructing a LBPool resource.
type LBPoolArgs struct {
	// Active health monitor Id. If one is not set, the active healthchecks will be disabled
	ActiveMonitorId pulumi.StringPtrInput
	// Load balancing algorithm controls how the incoming connections are distributed among the members
	Algorithm pulumi.StringPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
	MemberGroup LBPoolMemberGroupPtrInput
	// List of server pool members. Each pool member is identified, typically, by an IP address and a port
	Members LBPoolMemberArrayInput
	// The minimum number of members for the pool to be considered active
	MinActiveMembers pulumi.IntPtrInput
	// Passive health monitor Id. If one is not set, the passive healthchecks will be disabled
	PassiveMonitorId pulumi.StringPtrInput
	// SNAT translation configuration
	SnatTranslation LBPoolSnatTranslationPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBPoolTagArrayInput
	// TCP multiplexing allows the same TCP connection between load balancer and the backend server to be used for sending
	// multiple client requests from different client TCP connections
	TcpMultiplexingEnabled pulumi.BoolPtrInput
	// The maximum number of TCP connections per pool that are idly kept alive for sending future client requests
	TcpMultiplexingNumber pulumi.IntPtrInput
}

func (LBPoolArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*lbpoolArgs)(nil)).Elem()
}

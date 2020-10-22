// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type LBTCPVirtualServer struct {
	pulumi.CustomResourceState

	// Whether access log is enabled
	AccessLogEnabled pulumi.BoolPtrOutput `pulumi:"accessLogEnabled"`
	// The tcp application profile defines the application protocol characteristics
	ApplicationProfileId pulumi.StringOutput `pulumi:"applicationProfileId"`
	// Default pool member ports or port range
	DefaultPoolMemberPorts pulumi.StringArrayOutput `pulumi:"defaultPoolMemberPorts"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// whether the virtual server is enabled
	Enabled pulumi.BoolPtrOutput `pulumi:"enabled"`
	// virtual server IP address
	IpAddress pulumi.StringOutput `pulumi:"ipAddress"`
	// If not specified, connections are unlimited
	MaxConcurrentConnections pulumi.IntPtrOutput `pulumi:"maxConcurrentConnections"`
	// If not specified, connection rate is unlimited
	MaxNewConnectionRate pulumi.IntPtrOutput `pulumi:"maxNewConnectionRate"`
	// Persistence profile is used to allow related client connections to be sent to the same backend server. Source ip
	// persistence is supported.
	PersistenceProfileId pulumi.StringPtrOutput `pulumi:"persistenceProfileId"`
	// Server pool for backend connections
	PoolId pulumi.StringPtrOutput `pulumi:"poolId"`
	// Single port, multiple ports or port ranges
	Ports pulumi.StringArrayOutput `pulumi:"ports"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// When load balancer can not select a backend server to serve the request in default pool, the request would be served by
	// sorry server pool
	SorryPoolId pulumi.StringPtrOutput `pulumi:"sorryPoolId"`
	// Set of opaque identifiers meaningful to the user
	Tags LBTCPVirtualServerTagArrayOutput `pulumi:"tags"`
}

// NewLBTCPVirtualServer registers a new resource with the given unique name, arguments, and options.
func NewLBTCPVirtualServer(ctx *pulumi.Context,
	name string, args *LBTCPVirtualServerArgs, opts ...pulumi.ResourceOption) (*LBTCPVirtualServer, error) {
	if args == nil || args.ApplicationProfileId == nil {
		return nil, errors.New("missing required argument 'ApplicationProfileId'")
	}
	if args == nil || args.IpAddress == nil {
		return nil, errors.New("missing required argument 'IpAddress'")
	}
	if args == nil || args.Ports == nil {
		return nil, errors.New("missing required argument 'Ports'")
	}
	if args == nil {
		args = &LBTCPVirtualServerArgs{}
	}
	var resource LBTCPVirtualServer
	err := ctx.RegisterResource("nsxt:index/lBTCPVirtualServer:LBTCPVirtualServer", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLBTCPVirtualServer gets an existing LBTCPVirtualServer resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLBTCPVirtualServer(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LBTCPVirtualServerState, opts ...pulumi.ResourceOption) (*LBTCPVirtualServer, error) {
	var resource LBTCPVirtualServer
	err := ctx.ReadResource("nsxt:index/lBTCPVirtualServer:LBTCPVirtualServer", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LBTCPVirtualServer resources.
type lbtcpvirtualServerState struct {
	// Whether access log is enabled
	AccessLogEnabled *bool `pulumi:"accessLogEnabled"`
	// The tcp application profile defines the application protocol characteristics
	ApplicationProfileId *string `pulumi:"applicationProfileId"`
	// Default pool member ports or port range
	DefaultPoolMemberPorts []string `pulumi:"defaultPoolMemberPorts"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// whether the virtual server is enabled
	Enabled *bool `pulumi:"enabled"`
	// virtual server IP address
	IpAddress *string `pulumi:"ipAddress"`
	// If not specified, connections are unlimited
	MaxConcurrentConnections *int `pulumi:"maxConcurrentConnections"`
	// If not specified, connection rate is unlimited
	MaxNewConnectionRate *int `pulumi:"maxNewConnectionRate"`
	// Persistence profile is used to allow related client connections to be sent to the same backend server. Source ip
	// persistence is supported.
	PersistenceProfileId *string `pulumi:"persistenceProfileId"`
	// Server pool for backend connections
	PoolId *string `pulumi:"poolId"`
	// Single port, multiple ports or port ranges
	Ports []string `pulumi:"ports"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// When load balancer can not select a backend server to serve the request in default pool, the request would be served by
	// sorry server pool
	SorryPoolId *string `pulumi:"sorryPoolId"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBTCPVirtualServerTag `pulumi:"tags"`
}

type LBTCPVirtualServerState struct {
	// Whether access log is enabled
	AccessLogEnabled pulumi.BoolPtrInput
	// The tcp application profile defines the application protocol characteristics
	ApplicationProfileId pulumi.StringPtrInput
	// Default pool member ports or port range
	DefaultPoolMemberPorts pulumi.StringArrayInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// whether the virtual server is enabled
	Enabled pulumi.BoolPtrInput
	// virtual server IP address
	IpAddress pulumi.StringPtrInput
	// If not specified, connections are unlimited
	MaxConcurrentConnections pulumi.IntPtrInput
	// If not specified, connection rate is unlimited
	MaxNewConnectionRate pulumi.IntPtrInput
	// Persistence profile is used to allow related client connections to be sent to the same backend server. Source ip
	// persistence is supported.
	PersistenceProfileId pulumi.StringPtrInput
	// Server pool for backend connections
	PoolId pulumi.StringPtrInput
	// Single port, multiple ports or port ranges
	Ports pulumi.StringArrayInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// When load balancer can not select a backend server to serve the request in default pool, the request would be served by
	// sorry server pool
	SorryPoolId pulumi.StringPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBTCPVirtualServerTagArrayInput
}

func (LBTCPVirtualServerState) ElementType() reflect.Type {
	return reflect.TypeOf((*lbtcpvirtualServerState)(nil)).Elem()
}

type lbtcpvirtualServerArgs struct {
	// Whether access log is enabled
	AccessLogEnabled *bool `pulumi:"accessLogEnabled"`
	// The tcp application profile defines the application protocol characteristics
	ApplicationProfileId string `pulumi:"applicationProfileId"`
	// Default pool member ports or port range
	DefaultPoolMemberPorts []string `pulumi:"defaultPoolMemberPorts"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// whether the virtual server is enabled
	Enabled *bool `pulumi:"enabled"`
	// virtual server IP address
	IpAddress string `pulumi:"ipAddress"`
	// If not specified, connections are unlimited
	MaxConcurrentConnections *int `pulumi:"maxConcurrentConnections"`
	// If not specified, connection rate is unlimited
	MaxNewConnectionRate *int `pulumi:"maxNewConnectionRate"`
	// Persistence profile is used to allow related client connections to be sent to the same backend server. Source ip
	// persistence is supported.
	PersistenceProfileId *string `pulumi:"persistenceProfileId"`
	// Server pool for backend connections
	PoolId *string `pulumi:"poolId"`
	// Single port, multiple ports or port ranges
	Ports []string `pulumi:"ports"`
	// When load balancer can not select a backend server to serve the request in default pool, the request would be served by
	// sorry server pool
	SorryPoolId *string `pulumi:"sorryPoolId"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBTCPVirtualServerTag `pulumi:"tags"`
}

// The set of arguments for constructing a LBTCPVirtualServer resource.
type LBTCPVirtualServerArgs struct {
	// Whether access log is enabled
	AccessLogEnabled pulumi.BoolPtrInput
	// The tcp application profile defines the application protocol characteristics
	ApplicationProfileId pulumi.StringInput
	// Default pool member ports or port range
	DefaultPoolMemberPorts pulumi.StringArrayInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// whether the virtual server is enabled
	Enabled pulumi.BoolPtrInput
	// virtual server IP address
	IpAddress pulumi.StringInput
	// If not specified, connections are unlimited
	MaxConcurrentConnections pulumi.IntPtrInput
	// If not specified, connection rate is unlimited
	MaxNewConnectionRate pulumi.IntPtrInput
	// Persistence profile is used to allow related client connections to be sent to the same backend server. Source ip
	// persistence is supported.
	PersistenceProfileId pulumi.StringPtrInput
	// Server pool for backend connections
	PoolId pulumi.StringPtrInput
	// Single port, multiple ports or port ranges
	Ports pulumi.StringArrayInput
	// When load balancer can not select a backend server to serve the request in default pool, the request would be served by
	// sorry server pool
	SorryPoolId pulumi.StringPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBTCPVirtualServerTagArrayInput
}

func (LBTCPVirtualServerArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*lbtcpvirtualServerArgs)(nil)).Elem()
}
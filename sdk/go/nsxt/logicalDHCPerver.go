// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type LogicalDHCPerver struct {
	pulumi.CustomResourceState

	// Id of attached logical port
	AttachedLogicalPortId pulumi.StringOutput `pulumi:"attachedLogicalPortId"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// Generic DHCP options
	DhcpGenericOptions LogicalDHCPerverDhcpGenericOptionArrayOutput `pulumi:"dhcpGenericOptions"`
	// DHCP classless static routes
	DhcpOption121s LogicalDHCPerverDhcpOption121ArrayOutput `pulumi:"dhcpOption121s"`
	// DHCP profile uuid
	DhcpProfileId pulumi.StringOutput `pulumi:"dhcpProfileId"`
	// DHCP server ip in cidr format
	DhcpServerIp pulumi.StringOutput `pulumi:"dhcpServerIp"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// DNS IPs
	DnsNameServers pulumi.StringArrayOutput `pulumi:"dnsNameServers"`
	// Domain name
	DomainName pulumi.StringPtrOutput `pulumi:"domainName"`
	// Gateway IP
	GatewayIp pulumi.StringPtrOutput `pulumi:"gatewayIp"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags LogicalDHCPerverTagArrayOutput `pulumi:"tags"`
}

// NewLogicalDHCPerver registers a new resource with the given unique name, arguments, and options.
func NewLogicalDHCPerver(ctx *pulumi.Context,
	name string, args *LogicalDHCPerverArgs, opts ...pulumi.ResourceOption) (*LogicalDHCPerver, error) {
	if args == nil || args.DhcpProfileId == nil {
		return nil, errors.New("missing required argument 'DhcpProfileId'")
	}
	if args == nil || args.DhcpServerIp == nil {
		return nil, errors.New("missing required argument 'DhcpServerIp'")
	}
	if args == nil {
		args = &LogicalDHCPerverArgs{}
	}
	var resource LogicalDHCPerver
	err := ctx.RegisterResource("nsxt:index/logicalDHCPerver:LogicalDHCPerver", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLogicalDHCPerver gets an existing LogicalDHCPerver resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLogicalDHCPerver(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LogicalDHCPerverState, opts ...pulumi.ResourceOption) (*LogicalDHCPerver, error) {
	var resource LogicalDHCPerver
	err := ctx.ReadResource("nsxt:index/logicalDHCPerver:LogicalDHCPerver", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LogicalDHCPerver resources.
type logicalDHCPerverState struct {
	// Id of attached logical port
	AttachedLogicalPortId *string `pulumi:"attachedLogicalPortId"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// Generic DHCP options
	DhcpGenericOptions []LogicalDHCPerverDhcpGenericOption `pulumi:"dhcpGenericOptions"`
	// DHCP classless static routes
	DhcpOption121s []LogicalDHCPerverDhcpOption121 `pulumi:"dhcpOption121s"`
	// DHCP profile uuid
	DhcpProfileId *string `pulumi:"dhcpProfileId"`
	// DHCP server ip in cidr format
	DhcpServerIp *string `pulumi:"dhcpServerIp"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// DNS IPs
	DnsNameServers []string `pulumi:"dnsNameServers"`
	// Domain name
	DomainName *string `pulumi:"domainName"`
	// Gateway IP
	GatewayIp *string `pulumi:"gatewayIp"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []LogicalDHCPerverTag `pulumi:"tags"`
}

type LogicalDHCPerverState struct {
	// Id of attached logical port
	AttachedLogicalPortId pulumi.StringPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// Generic DHCP options
	DhcpGenericOptions LogicalDHCPerverDhcpGenericOptionArrayInput
	// DHCP classless static routes
	DhcpOption121s LogicalDHCPerverDhcpOption121ArrayInput
	// DHCP profile uuid
	DhcpProfileId pulumi.StringPtrInput
	// DHCP server ip in cidr format
	DhcpServerIp pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// DNS IPs
	DnsNameServers pulumi.StringArrayInput
	// Domain name
	DomainName pulumi.StringPtrInput
	// Gateway IP
	GatewayIp pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LogicalDHCPerverTagArrayInput
}

func (LogicalDHCPerverState) ElementType() reflect.Type {
	return reflect.TypeOf((*logicalDHCPerverState)(nil)).Elem()
}

type logicalDHCPerverArgs struct {
	// Description of this resource
	Description *string `pulumi:"description"`
	// Generic DHCP options
	DhcpGenericOptions []LogicalDHCPerverDhcpGenericOption `pulumi:"dhcpGenericOptions"`
	// DHCP classless static routes
	DhcpOption121s []LogicalDHCPerverDhcpOption121 `pulumi:"dhcpOption121s"`
	// DHCP profile uuid
	DhcpProfileId string `pulumi:"dhcpProfileId"`
	// DHCP server ip in cidr format
	DhcpServerIp string `pulumi:"dhcpServerIp"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// DNS IPs
	DnsNameServers []string `pulumi:"dnsNameServers"`
	// Domain name
	DomainName *string `pulumi:"domainName"`
	// Gateway IP
	GatewayIp *string `pulumi:"gatewayIp"`
	// Set of opaque identifiers meaningful to the user
	Tags []LogicalDHCPerverTag `pulumi:"tags"`
}

// The set of arguments for constructing a LogicalDHCPerver resource.
type LogicalDHCPerverArgs struct {
	// Description of this resource
	Description pulumi.StringPtrInput
	// Generic DHCP options
	DhcpGenericOptions LogicalDHCPerverDhcpGenericOptionArrayInput
	// DHCP classless static routes
	DhcpOption121s LogicalDHCPerverDhcpOption121ArrayInput
	// DHCP profile uuid
	DhcpProfileId pulumi.StringInput
	// DHCP server ip in cidr format
	DhcpServerIp pulumi.StringInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// DNS IPs
	DnsNameServers pulumi.StringArrayInput
	// Domain name
	DomainName pulumi.StringPtrInput
	// Gateway IP
	GatewayIp pulumi.StringPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LogicalDHCPerverTagArrayInput
}

func (LogicalDHCPerverArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*logicalDHCPerverArgs)(nil)).Elem()
}

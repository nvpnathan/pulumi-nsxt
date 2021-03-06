// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyTier0GatewayInterface struct {
	pulumi.CustomResourceState

	// Vlan ID
	AccessVlanId pulumi.IntPtrOutput `pulumi:"accessVlanId"`
	// Description for this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// Display name for this resource
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Policy path for edge node
	EdgeNodePath pulumi.StringPtrOutput `pulumi:"edgeNodePath"`
	// Enable Protocol Independent Multicast on Interface
	EnablePim pulumi.BoolPtrOutput `pulumi:"enablePim"`
	// Policy path for Tier0 gateway
	GatewayPath pulumi.StringOutput `pulumi:"gatewayPath"`
	// Ip addresses
	IpAddresses pulumi.StringArrayOutput `pulumi:"ipAddresses"`
	// The path of an IPv6 NDRA profile
	Ipv6NdraProfilePath pulumi.StringOutput `pulumi:"ipv6NdraProfilePath"`
	// Id of associated Gateway Locale Service on NSX
	LocaleServiceId pulumi.StringOutput `pulumi:"localeServiceId"`
	// Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
	Mtu pulumi.IntPtrOutput `pulumi:"mtu"`
	// NSX ID for this resource
	NsxId pulumi.StringOutput `pulumi:"nsxId"`
	// Policy path for this resource
	Path pulumi.StringOutput `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Policy path for connected segment
	SegmentPath pulumi.StringPtrOutput `pulumi:"segmentPath"`
	// Path of the site the Tier0 edge cluster belongs to
	SitePath pulumi.StringPtrOutput `pulumi:"sitePath"`
	// List of IP addresses and network prefixes for this interface
	Subnets pulumi.StringArrayOutput `pulumi:"subnets"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyTier0GatewayInterfaceTagArrayOutput `pulumi:"tags"`
	// Interface Type
	Type pulumi.StringPtrOutput `pulumi:"type"`
	// Unicast Reverse Path Forwarding mode
	UrpfMode pulumi.StringPtrOutput `pulumi:"urpfMode"`
}

// NewPolicyTier0GatewayInterface registers a new resource with the given unique name, arguments, and options.
func NewPolicyTier0GatewayInterface(ctx *pulumi.Context,
	name string, args *PolicyTier0GatewayInterfaceArgs, opts ...pulumi.ResourceOption) (*PolicyTier0GatewayInterface, error) {
	if args == nil || args.DisplayName == nil {
		return nil, errors.New("missing required argument 'DisplayName'")
	}
	if args == nil || args.GatewayPath == nil {
		return nil, errors.New("missing required argument 'GatewayPath'")
	}
	if args == nil || args.Subnets == nil {
		return nil, errors.New("missing required argument 'Subnets'")
	}
	if args == nil {
		args = &PolicyTier0GatewayInterfaceArgs{}
	}
	var resource PolicyTier0GatewayInterface
	err := ctx.RegisterResource("nsxt:index/policyTier0GatewayInterface:PolicyTier0GatewayInterface", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyTier0GatewayInterface gets an existing PolicyTier0GatewayInterface resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyTier0GatewayInterface(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyTier0GatewayInterfaceState, opts ...pulumi.ResourceOption) (*PolicyTier0GatewayInterface, error) {
	var resource PolicyTier0GatewayInterface
	err := ctx.ReadResource("nsxt:index/policyTier0GatewayInterface:PolicyTier0GatewayInterface", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyTier0GatewayInterface resources.
type policyTier0GatewayInterfaceState struct {
	// Vlan ID
	AccessVlanId *int `pulumi:"accessVlanId"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName *string `pulumi:"displayName"`
	// Policy path for edge node
	EdgeNodePath *string `pulumi:"edgeNodePath"`
	// Enable Protocol Independent Multicast on Interface
	EnablePim *bool `pulumi:"enablePim"`
	// Policy path for Tier0 gateway
	GatewayPath *string `pulumi:"gatewayPath"`
	// Ip addresses
	IpAddresses []string `pulumi:"ipAddresses"`
	// The path of an IPv6 NDRA profile
	Ipv6NdraProfilePath *string `pulumi:"ipv6NdraProfilePath"`
	// Id of associated Gateway Locale Service on NSX
	LocaleServiceId *string `pulumi:"localeServiceId"`
	// Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
	Mtu *int `pulumi:"mtu"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path for this resource
	Path *string `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Policy path for connected segment
	SegmentPath *string `pulumi:"segmentPath"`
	// Path of the site the Tier0 edge cluster belongs to
	SitePath *string `pulumi:"sitePath"`
	// List of IP addresses and network prefixes for this interface
	Subnets []string `pulumi:"subnets"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyTier0GatewayInterfaceTag `pulumi:"tags"`
	// Interface Type
	Type *string `pulumi:"type"`
	// Unicast Reverse Path Forwarding mode
	UrpfMode *string `pulumi:"urpfMode"`
}

type PolicyTier0GatewayInterfaceState struct {
	// Vlan ID
	AccessVlanId pulumi.IntPtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringPtrInput
	// Policy path for edge node
	EdgeNodePath pulumi.StringPtrInput
	// Enable Protocol Independent Multicast on Interface
	EnablePim pulumi.BoolPtrInput
	// Policy path for Tier0 gateway
	GatewayPath pulumi.StringPtrInput
	// Ip addresses
	IpAddresses pulumi.StringArrayInput
	// The path of an IPv6 NDRA profile
	Ipv6NdraProfilePath pulumi.StringPtrInput
	// Id of associated Gateway Locale Service on NSX
	LocaleServiceId pulumi.StringPtrInput
	// Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
	Mtu pulumi.IntPtrInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path for this resource
	Path pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Policy path for connected segment
	SegmentPath pulumi.StringPtrInput
	// Path of the site the Tier0 edge cluster belongs to
	SitePath pulumi.StringPtrInput
	// List of IP addresses and network prefixes for this interface
	Subnets pulumi.StringArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyTier0GatewayInterfaceTagArrayInput
	// Interface Type
	Type pulumi.StringPtrInput
	// Unicast Reverse Path Forwarding mode
	UrpfMode pulumi.StringPtrInput
}

func (PolicyTier0GatewayInterfaceState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyTier0GatewayInterfaceState)(nil)).Elem()
}

type policyTier0GatewayInterfaceArgs struct {
	// Vlan ID
	AccessVlanId *int `pulumi:"accessVlanId"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName string `pulumi:"displayName"`
	// Policy path for edge node
	EdgeNodePath *string `pulumi:"edgeNodePath"`
	// Enable Protocol Independent Multicast on Interface
	EnablePim *bool `pulumi:"enablePim"`
	// Policy path for Tier0 gateway
	GatewayPath string `pulumi:"gatewayPath"`
	// The path of an IPv6 NDRA profile
	Ipv6NdraProfilePath *string `pulumi:"ipv6NdraProfilePath"`
	// Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
	Mtu *int `pulumi:"mtu"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path for connected segment
	SegmentPath *string `pulumi:"segmentPath"`
	// Path of the site the Tier0 edge cluster belongs to
	SitePath *string `pulumi:"sitePath"`
	// List of IP addresses and network prefixes for this interface
	Subnets []string `pulumi:"subnets"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyTier0GatewayInterfaceTag `pulumi:"tags"`
	// Interface Type
	Type *string `pulumi:"type"`
	// Unicast Reverse Path Forwarding mode
	UrpfMode *string `pulumi:"urpfMode"`
}

// The set of arguments for constructing a PolicyTier0GatewayInterface resource.
type PolicyTier0GatewayInterfaceArgs struct {
	// Vlan ID
	AccessVlanId pulumi.IntPtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringInput
	// Policy path for edge node
	EdgeNodePath pulumi.StringPtrInput
	// Enable Protocol Independent Multicast on Interface
	EnablePim pulumi.BoolPtrInput
	// Policy path for Tier0 gateway
	GatewayPath pulumi.StringInput
	// The path of an IPv6 NDRA profile
	Ipv6NdraProfilePath pulumi.StringPtrInput
	// Maximum transmission unit specifies the size of the largest packet that a network protocol can transmit
	Mtu pulumi.IntPtrInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path for connected segment
	SegmentPath pulumi.StringPtrInput
	// Path of the site the Tier0 edge cluster belongs to
	SitePath pulumi.StringPtrInput
	// List of IP addresses and network prefixes for this interface
	Subnets pulumi.StringArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyTier0GatewayInterfaceTagArrayInput
	// Interface Type
	Type pulumi.StringPtrInput
	// Unicast Reverse Path Forwarding mode
	UrpfMode pulumi.StringPtrInput
}

func (PolicyTier0GatewayInterfaceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyTier0GatewayInterfaceArgs)(nil)).Elem()
}

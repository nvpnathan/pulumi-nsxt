// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type SwitchSecuritySwitchingProfile struct {
	pulumi.CustomResourceState

	// Indicates whether DHCP client blocking is enabled
	BlockClientDhcp pulumi.BoolPtrOutput `pulumi:"blockClientDhcp"`
	// Block all traffic except IP/(G)ARP/BPDU
	BlockNonIp pulumi.BoolPtrOutput `pulumi:"blockNonIp"`
	// Indicates whether DHCP server blocking is enabled
	BlockServerDhcp pulumi.BoolPtrOutput `pulumi:"blockServerDhcp"`
	// Indicates whether BPDU filter is enabled
	BpduFilterEnabled pulumi.BoolPtrOutput `pulumi:"bpduFilterEnabled"`
	// Set of allowed MAC addresses to be excluded from BPDU filtering
	BpduFilterWhitelists pulumi.StringArrayOutput `pulumi:"bpduFilterWhitelists"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput                               `pulumi:"displayName"`
	RateLimits  SwitchSecuritySwitchingProfileRateLimitsPtrOutput `pulumi:"rateLimits"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags SwitchSecuritySwitchingProfileTagArrayOutput `pulumi:"tags"`
}

// NewSwitchSecuritySwitchingProfile registers a new resource with the given unique name, arguments, and options.
func NewSwitchSecuritySwitchingProfile(ctx *pulumi.Context,
	name string, args *SwitchSecuritySwitchingProfileArgs, opts ...pulumi.ResourceOption) (*SwitchSecuritySwitchingProfile, error) {
	if args == nil {
		args = &SwitchSecuritySwitchingProfileArgs{}
	}
	var resource SwitchSecuritySwitchingProfile
	err := ctx.RegisterResource("nsxt:index/switchSecuritySwitchingProfile:SwitchSecuritySwitchingProfile", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSwitchSecuritySwitchingProfile gets an existing SwitchSecuritySwitchingProfile resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSwitchSecuritySwitchingProfile(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SwitchSecuritySwitchingProfileState, opts ...pulumi.ResourceOption) (*SwitchSecuritySwitchingProfile, error) {
	var resource SwitchSecuritySwitchingProfile
	err := ctx.ReadResource("nsxt:index/switchSecuritySwitchingProfile:SwitchSecuritySwitchingProfile", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SwitchSecuritySwitchingProfile resources.
type switchSecuritySwitchingProfileState struct {
	// Indicates whether DHCP client blocking is enabled
	BlockClientDhcp *bool `pulumi:"blockClientDhcp"`
	// Block all traffic except IP/(G)ARP/BPDU
	BlockNonIp *bool `pulumi:"blockNonIp"`
	// Indicates whether DHCP server blocking is enabled
	BlockServerDhcp *bool `pulumi:"blockServerDhcp"`
	// Indicates whether BPDU filter is enabled
	BpduFilterEnabled *bool `pulumi:"bpduFilterEnabled"`
	// Set of allowed MAC addresses to be excluded from BPDU filtering
	BpduFilterWhitelists []string `pulumi:"bpduFilterWhitelists"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string                                   `pulumi:"displayName"`
	RateLimits  *SwitchSecuritySwitchingProfileRateLimits `pulumi:"rateLimits"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []SwitchSecuritySwitchingProfileTag `pulumi:"tags"`
}

type SwitchSecuritySwitchingProfileState struct {
	// Indicates whether DHCP client blocking is enabled
	BlockClientDhcp pulumi.BoolPtrInput
	// Block all traffic except IP/(G)ARP/BPDU
	BlockNonIp pulumi.BoolPtrInput
	// Indicates whether DHCP server blocking is enabled
	BlockServerDhcp pulumi.BoolPtrInput
	// Indicates whether BPDU filter is enabled
	BpduFilterEnabled pulumi.BoolPtrInput
	// Set of allowed MAC addresses to be excluded from BPDU filtering
	BpduFilterWhitelists pulumi.StringArrayInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	RateLimits  SwitchSecuritySwitchingProfileRateLimitsPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags SwitchSecuritySwitchingProfileTagArrayInput
}

func (SwitchSecuritySwitchingProfileState) ElementType() reflect.Type {
	return reflect.TypeOf((*switchSecuritySwitchingProfileState)(nil)).Elem()
}

type switchSecuritySwitchingProfileArgs struct {
	// Indicates whether DHCP client blocking is enabled
	BlockClientDhcp *bool `pulumi:"blockClientDhcp"`
	// Block all traffic except IP/(G)ARP/BPDU
	BlockNonIp *bool `pulumi:"blockNonIp"`
	// Indicates whether DHCP server blocking is enabled
	BlockServerDhcp *bool `pulumi:"blockServerDhcp"`
	// Indicates whether BPDU filter is enabled
	BpduFilterEnabled *bool `pulumi:"bpduFilterEnabled"`
	// Set of allowed MAC addresses to be excluded from BPDU filtering
	BpduFilterWhitelists []string `pulumi:"bpduFilterWhitelists"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string                                   `pulumi:"displayName"`
	RateLimits  *SwitchSecuritySwitchingProfileRateLimits `pulumi:"rateLimits"`
	// Set of opaque identifiers meaningful to the user
	Tags []SwitchSecuritySwitchingProfileTag `pulumi:"tags"`
}

// The set of arguments for constructing a SwitchSecuritySwitchingProfile resource.
type SwitchSecuritySwitchingProfileArgs struct {
	// Indicates whether DHCP client blocking is enabled
	BlockClientDhcp pulumi.BoolPtrInput
	// Block all traffic except IP/(G)ARP/BPDU
	BlockNonIp pulumi.BoolPtrInput
	// Indicates whether DHCP server blocking is enabled
	BlockServerDhcp pulumi.BoolPtrInput
	// Indicates whether BPDU filter is enabled
	BpduFilterEnabled pulumi.BoolPtrInput
	// Set of allowed MAC addresses to be excluded from BPDU filtering
	BpduFilterWhitelists pulumi.StringArrayInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	RateLimits  SwitchSecuritySwitchingProfileRateLimitsPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags SwitchSecuritySwitchingProfileTagArrayInput
}

func (SwitchSecuritySwitchingProfileArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*switchSecuritySwitchingProfileArgs)(nil)).Elem()
}

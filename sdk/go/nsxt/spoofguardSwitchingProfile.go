// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type SpoofguardSwitchingProfile struct {
	pulumi.CustomResourceState

	// When true, this profile overrides the default system wide settings for Spoof Guard when assigned to ports
	AddressBindingWhitelistEnabled pulumi.BoolPtrOutput `pulumi:"addressBindingWhitelistEnabled"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags SpoofguardSwitchingProfileTagArrayOutput `pulumi:"tags"`
}

// NewSpoofguardSwitchingProfile registers a new resource with the given unique name, arguments, and options.
func NewSpoofguardSwitchingProfile(ctx *pulumi.Context,
	name string, args *SpoofguardSwitchingProfileArgs, opts ...pulumi.ResourceOption) (*SpoofguardSwitchingProfile, error) {
	if args == nil {
		args = &SpoofguardSwitchingProfileArgs{}
	}
	var resource SpoofguardSwitchingProfile
	err := ctx.RegisterResource("nsxt:index/spoofguardSwitchingProfile:SpoofguardSwitchingProfile", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetSpoofguardSwitchingProfile gets an existing SpoofguardSwitchingProfile resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetSpoofguardSwitchingProfile(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *SpoofguardSwitchingProfileState, opts ...pulumi.ResourceOption) (*SpoofguardSwitchingProfile, error) {
	var resource SpoofguardSwitchingProfile
	err := ctx.ReadResource("nsxt:index/spoofguardSwitchingProfile:SpoofguardSwitchingProfile", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering SpoofguardSwitchingProfile resources.
type spoofguardSwitchingProfileState struct {
	// When true, this profile overrides the default system wide settings for Spoof Guard when assigned to ports
	AddressBindingWhitelistEnabled *bool `pulumi:"addressBindingWhitelistEnabled"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []SpoofguardSwitchingProfileTag `pulumi:"tags"`
}

type SpoofguardSwitchingProfileState struct {
	// When true, this profile overrides the default system wide settings for Spoof Guard when assigned to ports
	AddressBindingWhitelistEnabled pulumi.BoolPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags SpoofguardSwitchingProfileTagArrayInput
}

func (SpoofguardSwitchingProfileState) ElementType() reflect.Type {
	return reflect.TypeOf((*spoofguardSwitchingProfileState)(nil)).Elem()
}

type spoofguardSwitchingProfileArgs struct {
	// When true, this profile overrides the default system wide settings for Spoof Guard when assigned to ports
	AddressBindingWhitelistEnabled *bool `pulumi:"addressBindingWhitelistEnabled"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// Set of opaque identifiers meaningful to the user
	Tags []SpoofguardSwitchingProfileTag `pulumi:"tags"`
}

// The set of arguments for constructing a SpoofguardSwitchingProfile resource.
type SpoofguardSwitchingProfileArgs struct {
	// When true, this profile overrides the default system wide settings for Spoof Guard when assigned to ports
	AddressBindingWhitelistEnabled pulumi.BoolPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags SpoofguardSwitchingProfileTagArrayInput
}

func (SpoofguardSwitchingProfileArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*spoofguardSwitchingProfileArgs)(nil)).Elem()
}
// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type QOSSwitchingProfile struct {
	pulumi.CustomResourceState

	// Class of service
	ClassOfService pulumi.IntPtrOutput `pulumi:"classOfService"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// DSCP Priority
	DscpPriority pulumi.IntPtrOutput `pulumi:"dscpPriority"`
	// Trust mode for DSCP
	DscpTrusted                pulumi.BoolPtrOutput                                   `pulumi:"dscpTrusted"`
	EgressRateShaper           QOSSwitchingProfileEgressRateShaperPtrOutput           `pulumi:"egressRateShaper"`
	IngressBroadcastRateShaper QOSSwitchingProfileIngressBroadcastRateShaperPtrOutput `pulumi:"ingressBroadcastRateShaper"`
	IngressRateShaper          QOSSwitchingProfileIngressRateShaperPtrOutput          `pulumi:"ingressRateShaper"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags QOSSwitchingProfileTagArrayOutput `pulumi:"tags"`
}

// NewQOSSwitchingProfile registers a new resource with the given unique name, arguments, and options.
func NewQOSSwitchingProfile(ctx *pulumi.Context,
	name string, args *QOSSwitchingProfileArgs, opts ...pulumi.ResourceOption) (*QOSSwitchingProfile, error) {
	if args == nil {
		args = &QOSSwitchingProfileArgs{}
	}
	var resource QOSSwitchingProfile
	err := ctx.RegisterResource("nsxt:index/qOSSwitchingProfile:QOSSwitchingProfile", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetQOSSwitchingProfile gets an existing QOSSwitchingProfile resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetQOSSwitchingProfile(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *QOSSwitchingProfileState, opts ...pulumi.ResourceOption) (*QOSSwitchingProfile, error) {
	var resource QOSSwitchingProfile
	err := ctx.ReadResource("nsxt:index/qOSSwitchingProfile:QOSSwitchingProfile", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering QOSSwitchingProfile resources.
type qosswitchingProfileState struct {
	// Class of service
	ClassOfService *int `pulumi:"classOfService"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// DSCP Priority
	DscpPriority *int `pulumi:"dscpPriority"`
	// Trust mode for DSCP
	DscpTrusted                *bool                                          `pulumi:"dscpTrusted"`
	EgressRateShaper           *QOSSwitchingProfileEgressRateShaper           `pulumi:"egressRateShaper"`
	IngressBroadcastRateShaper *QOSSwitchingProfileIngressBroadcastRateShaper `pulumi:"ingressBroadcastRateShaper"`
	IngressRateShaper          *QOSSwitchingProfileIngressRateShaper          `pulumi:"ingressRateShaper"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []QOSSwitchingProfileTag `pulumi:"tags"`
}

type QOSSwitchingProfileState struct {
	// Class of service
	ClassOfService pulumi.IntPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// DSCP Priority
	DscpPriority pulumi.IntPtrInput
	// Trust mode for DSCP
	DscpTrusted                pulumi.BoolPtrInput
	EgressRateShaper           QOSSwitchingProfileEgressRateShaperPtrInput
	IngressBroadcastRateShaper QOSSwitchingProfileIngressBroadcastRateShaperPtrInput
	IngressRateShaper          QOSSwitchingProfileIngressRateShaperPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags QOSSwitchingProfileTagArrayInput
}

func (QOSSwitchingProfileState) ElementType() reflect.Type {
	return reflect.TypeOf((*qosswitchingProfileState)(nil)).Elem()
}

type qosswitchingProfileArgs struct {
	// Class of service
	ClassOfService *int `pulumi:"classOfService"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// DSCP Priority
	DscpPriority *int `pulumi:"dscpPriority"`
	// Trust mode for DSCP
	DscpTrusted                *bool                                          `pulumi:"dscpTrusted"`
	EgressRateShaper           *QOSSwitchingProfileEgressRateShaper           `pulumi:"egressRateShaper"`
	IngressBroadcastRateShaper *QOSSwitchingProfileIngressBroadcastRateShaper `pulumi:"ingressBroadcastRateShaper"`
	IngressRateShaper          *QOSSwitchingProfileIngressRateShaper          `pulumi:"ingressRateShaper"`
	// Set of opaque identifiers meaningful to the user
	Tags []QOSSwitchingProfileTag `pulumi:"tags"`
}

// The set of arguments for constructing a QOSSwitchingProfile resource.
type QOSSwitchingProfileArgs struct {
	// Class of service
	ClassOfService pulumi.IntPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// DSCP Priority
	DscpPriority pulumi.IntPtrInput
	// Trust mode for DSCP
	DscpTrusted                pulumi.BoolPtrInput
	EgressRateShaper           QOSSwitchingProfileEgressRateShaperPtrInput
	IngressBroadcastRateShaper QOSSwitchingProfileIngressBroadcastRateShaperPtrInput
	IngressRateShaper          QOSSwitchingProfileIngressRateShaperPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags QOSSwitchingProfileTagArrayInput
}

func (QOSSwitchingProfileArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*qosswitchingProfileArgs)(nil)).Elem()
}
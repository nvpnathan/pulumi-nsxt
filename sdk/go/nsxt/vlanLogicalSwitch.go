// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type VlanLogicalSwitch struct {
	pulumi.CustomResourceState

	// Address bindings for the Logical switch
	AddressBindings VlanLogicalSwitchAddressBindingArrayOutput `pulumi:"addressBindings"`
	// Represents Desired state of the object
	AdminState pulumi.StringPtrOutput `pulumi:"adminState"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// IP pool id that associated with a LogicalSwitch
	IpPoolId pulumi.StringPtrOutput `pulumi:"ipPoolId"`
	// Mac pool id that associated with a LogicalSwitch
	MacPoolId pulumi.StringPtrOutput `pulumi:"macPoolId"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
	// be used if not specified
	SwitchingProfileIds VlanLogicalSwitchSwitchingProfileIdArrayOutput `pulumi:"switchingProfileIds"`
	// Set of opaque identifiers meaningful to the user
	Tags VlanLogicalSwitchTagArrayOutput `pulumi:"tags"`
	// Id of the TransportZone to which this LogicalSwitch is associated
	TransportZoneId pulumi.StringOutput `pulumi:"transportZoneId"`
	// VLAN Id
	Vlan pulumi.IntOutput `pulumi:"vlan"`
}

// NewVlanLogicalSwitch registers a new resource with the given unique name, arguments, and options.
func NewVlanLogicalSwitch(ctx *pulumi.Context,
	name string, args *VlanLogicalSwitchArgs, opts ...pulumi.ResourceOption) (*VlanLogicalSwitch, error) {
	if args == nil || args.TransportZoneId == nil {
		return nil, errors.New("missing required argument 'TransportZoneId'")
	}
	if args == nil || args.Vlan == nil {
		return nil, errors.New("missing required argument 'Vlan'")
	}
	if args == nil {
		args = &VlanLogicalSwitchArgs{}
	}
	var resource VlanLogicalSwitch
	err := ctx.RegisterResource("nsxt:index/vlanLogicalSwitch:VlanLogicalSwitch", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetVlanLogicalSwitch gets an existing VlanLogicalSwitch resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetVlanLogicalSwitch(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *VlanLogicalSwitchState, opts ...pulumi.ResourceOption) (*VlanLogicalSwitch, error) {
	var resource VlanLogicalSwitch
	err := ctx.ReadResource("nsxt:index/vlanLogicalSwitch:VlanLogicalSwitch", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering VlanLogicalSwitch resources.
type vlanLogicalSwitchState struct {
	// Address bindings for the Logical switch
	AddressBindings []VlanLogicalSwitchAddressBinding `pulumi:"addressBindings"`
	// Represents Desired state of the object
	AdminState *string `pulumi:"adminState"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// IP pool id that associated with a LogicalSwitch
	IpPoolId *string `pulumi:"ipPoolId"`
	// Mac pool id that associated with a LogicalSwitch
	MacPoolId *string `pulumi:"macPoolId"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
	// be used if not specified
	SwitchingProfileIds []VlanLogicalSwitchSwitchingProfileId `pulumi:"switchingProfileIds"`
	// Set of opaque identifiers meaningful to the user
	Tags []VlanLogicalSwitchTag `pulumi:"tags"`
	// Id of the TransportZone to which this LogicalSwitch is associated
	TransportZoneId *string `pulumi:"transportZoneId"`
	// VLAN Id
	Vlan *int `pulumi:"vlan"`
}

type VlanLogicalSwitchState struct {
	// Address bindings for the Logical switch
	AddressBindings VlanLogicalSwitchAddressBindingArrayInput
	// Represents Desired state of the object
	AdminState pulumi.StringPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// IP pool id that associated with a LogicalSwitch
	IpPoolId pulumi.StringPtrInput
	// Mac pool id that associated with a LogicalSwitch
	MacPoolId pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
	// be used if not specified
	SwitchingProfileIds VlanLogicalSwitchSwitchingProfileIdArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags VlanLogicalSwitchTagArrayInput
	// Id of the TransportZone to which this LogicalSwitch is associated
	TransportZoneId pulumi.StringPtrInput
	// VLAN Id
	Vlan pulumi.IntPtrInput
}

func (VlanLogicalSwitchState) ElementType() reflect.Type {
	return reflect.TypeOf((*vlanLogicalSwitchState)(nil)).Elem()
}

type vlanLogicalSwitchArgs struct {
	// Address bindings for the Logical switch
	AddressBindings []VlanLogicalSwitchAddressBinding `pulumi:"addressBindings"`
	// Represents Desired state of the object
	AdminState *string `pulumi:"adminState"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// IP pool id that associated with a LogicalSwitch
	IpPoolId *string `pulumi:"ipPoolId"`
	// Mac pool id that associated with a LogicalSwitch
	MacPoolId *string `pulumi:"macPoolId"`
	// List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
	// be used if not specified
	SwitchingProfileIds []VlanLogicalSwitchSwitchingProfileId `pulumi:"switchingProfileIds"`
	// Set of opaque identifiers meaningful to the user
	Tags []VlanLogicalSwitchTag `pulumi:"tags"`
	// Id of the TransportZone to which this LogicalSwitch is associated
	TransportZoneId string `pulumi:"transportZoneId"`
	// VLAN Id
	Vlan int `pulumi:"vlan"`
}

// The set of arguments for constructing a VlanLogicalSwitch resource.
type VlanLogicalSwitchArgs struct {
	// Address bindings for the Logical switch
	AddressBindings VlanLogicalSwitchAddressBindingArrayInput
	// Represents Desired state of the object
	AdminState pulumi.StringPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// IP pool id that associated with a LogicalSwitch
	IpPoolId pulumi.StringPtrInput
	// Mac pool id that associated with a LogicalSwitch
	MacPoolId pulumi.StringPtrInput
	// List of IDs of switching profiles (of various types) to be associated with this object. Default switching profiles will
	// be used if not specified
	SwitchingProfileIds VlanLogicalSwitchSwitchingProfileIdArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags VlanLogicalSwitchTagArrayInput
	// Id of the TransportZone to which this LogicalSwitch is associated
	TransportZoneId pulumi.StringInput
	// VLAN Id
	Vlan pulumi.IntInput
}

func (VlanLogicalSwitchArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*vlanLogicalSwitchArgs)(nil)).Elem()
}

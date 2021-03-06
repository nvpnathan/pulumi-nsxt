// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type IPProtocolNSService struct {
	pulumi.CustomResourceState

	// A boolean flag which reflects whether this is a default NSServices which can't be modified/deleted
	DefaultService pulumi.BoolOutput `pulumi:"defaultService"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// IP protocol number
	Protocol pulumi.IntOutput `pulumi:"protocol"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags IPProtocolNSServiceTagArrayOutput `pulumi:"tags"`
}

// NewIPProtocolNSService registers a new resource with the given unique name, arguments, and options.
func NewIPProtocolNSService(ctx *pulumi.Context,
	name string, args *IPProtocolNSServiceArgs, opts ...pulumi.ResourceOption) (*IPProtocolNSService, error) {
	if args == nil || args.Protocol == nil {
		return nil, errors.New("missing required argument 'Protocol'")
	}
	if args == nil {
		args = &IPProtocolNSServiceArgs{}
	}
	var resource IPProtocolNSService
	err := ctx.RegisterResource("nsxt:index/iPProtocolNSService:IPProtocolNSService", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetIPProtocolNSService gets an existing IPProtocolNSService resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetIPProtocolNSService(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *IPProtocolNSServiceState, opts ...pulumi.ResourceOption) (*IPProtocolNSService, error) {
	var resource IPProtocolNSService
	err := ctx.ReadResource("nsxt:index/iPProtocolNSService:IPProtocolNSService", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering IPProtocolNSService resources.
type ipprotocolNSServiceState struct {
	// A boolean flag which reflects whether this is a default NSServices which can't be modified/deleted
	DefaultService *bool `pulumi:"defaultService"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// IP protocol number
	Protocol *int `pulumi:"protocol"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []IPProtocolNSServiceTag `pulumi:"tags"`
}

type IPProtocolNSServiceState struct {
	// A boolean flag which reflects whether this is a default NSServices which can't be modified/deleted
	DefaultService pulumi.BoolPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// IP protocol number
	Protocol pulumi.IntPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags IPProtocolNSServiceTagArrayInput
}

func (IPProtocolNSServiceState) ElementType() reflect.Type {
	return reflect.TypeOf((*ipprotocolNSServiceState)(nil)).Elem()
}

type ipprotocolNSServiceArgs struct {
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// IP protocol number
	Protocol int `pulumi:"protocol"`
	// Set of opaque identifiers meaningful to the user
	Tags []IPProtocolNSServiceTag `pulumi:"tags"`
}

// The set of arguments for constructing a IPProtocolNSService resource.
type IPProtocolNSServiceArgs struct {
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// IP protocol number
	Protocol pulumi.IntInput
	// Set of opaque identifiers meaningful to the user
	Tags IPProtocolNSServiceTagArrayInput
}

func (IPProtocolNSServiceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ipprotocolNSServiceArgs)(nil)).Elem()
}

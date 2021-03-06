// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyLBService struct {
	pulumi.CustomResourceState

	// Policy path for connected policy object
	ConnectivityPath pulumi.StringPtrOutput `pulumi:"connectivityPath"`
	// Description for this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// Display name for this resource
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Flag to enable the Service
	Enabled pulumi.BoolPtrOutput `pulumi:"enabled"`
	// Log level for Load Balancer Service messages
	ErrorLogLevel pulumi.StringPtrOutput `pulumi:"errorLogLevel"`
	// NSX ID for this resource
	NsxId pulumi.StringOutput `pulumi:"nsxId"`
	// Policy path for this resource
	Path pulumi.StringOutput `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Load Balancer Service size
	Size pulumi.StringPtrOutput `pulumi:"size"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyLBServiceTagArrayOutput `pulumi:"tags"`
}

// NewPolicyLBService registers a new resource with the given unique name, arguments, and options.
func NewPolicyLBService(ctx *pulumi.Context,
	name string, args *PolicyLBServiceArgs, opts ...pulumi.ResourceOption) (*PolicyLBService, error) {
	if args == nil || args.DisplayName == nil {
		return nil, errors.New("missing required argument 'DisplayName'")
	}
	if args == nil {
		args = &PolicyLBServiceArgs{}
	}
	var resource PolicyLBService
	err := ctx.RegisterResource("nsxt:index/policyLBService:PolicyLBService", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyLBService gets an existing PolicyLBService resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyLBService(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyLBServiceState, opts ...pulumi.ResourceOption) (*PolicyLBService, error) {
	var resource PolicyLBService
	err := ctx.ReadResource("nsxt:index/policyLBService:PolicyLBService", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyLBService resources.
type policyLBServiceState struct {
	// Policy path for connected policy object
	ConnectivityPath *string `pulumi:"connectivityPath"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName *string `pulumi:"displayName"`
	// Flag to enable the Service
	Enabled *bool `pulumi:"enabled"`
	// Log level for Load Balancer Service messages
	ErrorLogLevel *string `pulumi:"errorLogLevel"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path for this resource
	Path *string `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Load Balancer Service size
	Size *string `pulumi:"size"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyLBServiceTag `pulumi:"tags"`
}

type PolicyLBServiceState struct {
	// Policy path for connected policy object
	ConnectivityPath pulumi.StringPtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringPtrInput
	// Flag to enable the Service
	Enabled pulumi.BoolPtrInput
	// Log level for Load Balancer Service messages
	ErrorLogLevel pulumi.StringPtrInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path for this resource
	Path pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Load Balancer Service size
	Size pulumi.StringPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyLBServiceTagArrayInput
}

func (PolicyLBServiceState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyLBServiceState)(nil)).Elem()
}

type policyLBServiceArgs struct {
	// Policy path for connected policy object
	ConnectivityPath *string `pulumi:"connectivityPath"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName string `pulumi:"displayName"`
	// Flag to enable the Service
	Enabled *bool `pulumi:"enabled"`
	// Log level for Load Balancer Service messages
	ErrorLogLevel *string `pulumi:"errorLogLevel"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Load Balancer Service size
	Size *string `pulumi:"size"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyLBServiceTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyLBService resource.
type PolicyLBServiceArgs struct {
	// Policy path for connected policy object
	ConnectivityPath pulumi.StringPtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringInput
	// Flag to enable the Service
	Enabled pulumi.BoolPtrInput
	// Log level for Load Balancer Service messages
	ErrorLogLevel pulumi.StringPtrInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Load Balancer Service size
	Size pulumi.StringPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyLBServiceTagArrayInput
}

func (PolicyLBServiceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyLBServiceArgs)(nil)).Elem()
}

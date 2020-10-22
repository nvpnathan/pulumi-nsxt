// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyService struct {
	pulumi.CustomResourceState

	// Algorithm type service entry
	AlgorithmEntries PolicyServiceAlgorithmEntryArrayOutput `pulumi:"algorithmEntries"`
	// Description for this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// Display name for this resource
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Ether type service entry
	EtherTypeEntries PolicyServiceEtherTypeEntryArrayOutput `pulumi:"etherTypeEntries"`
	// ICMP type service entry
	IcmpEntries PolicyServiceIcmpEntryArrayOutput `pulumi:"icmpEntries"`
	// IGMP type service entry
	IgmpEntries PolicyServiceIgmpEntryArrayOutput `pulumi:"igmpEntries"`
	// IP Protocol type service entry
	IpProtocolEntries PolicyServiceIpProtocolEntryArrayOutput `pulumi:"ipProtocolEntries"`
	// L4 port set type service entry
	L4PortSetEntries PolicyServiceL4PortSetEntryArrayOutput `pulumi:"l4PortSetEntries"`
	// NSX ID for this resource
	NsxId pulumi.StringOutput `pulumi:"nsxId"`
	// Policy path for this resource
	Path pulumi.StringOutput `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyServiceTagArrayOutput `pulumi:"tags"`
}

// NewPolicyService registers a new resource with the given unique name, arguments, and options.
func NewPolicyService(ctx *pulumi.Context,
	name string, args *PolicyServiceArgs, opts ...pulumi.ResourceOption) (*PolicyService, error) {
	if args == nil || args.DisplayName == nil {
		return nil, errors.New("missing required argument 'DisplayName'")
	}
	if args == nil {
		args = &PolicyServiceArgs{}
	}
	var resource PolicyService
	err := ctx.RegisterResource("nsxt:index/policyService:PolicyService", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyService gets an existing PolicyService resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyService(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyServiceState, opts ...pulumi.ResourceOption) (*PolicyService, error) {
	var resource PolicyService
	err := ctx.ReadResource("nsxt:index/policyService:PolicyService", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyService resources.
type policyServiceState struct {
	// Algorithm type service entry
	AlgorithmEntries []PolicyServiceAlgorithmEntry `pulumi:"algorithmEntries"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName *string `pulumi:"displayName"`
	// Ether type service entry
	EtherTypeEntries []PolicyServiceEtherTypeEntry `pulumi:"etherTypeEntries"`
	// ICMP type service entry
	IcmpEntries []PolicyServiceIcmpEntry `pulumi:"icmpEntries"`
	// IGMP type service entry
	IgmpEntries []PolicyServiceIgmpEntry `pulumi:"igmpEntries"`
	// IP Protocol type service entry
	IpProtocolEntries []PolicyServiceIpProtocolEntry `pulumi:"ipProtocolEntries"`
	// L4 port set type service entry
	L4PortSetEntries []PolicyServiceL4PortSetEntry `pulumi:"l4PortSetEntries"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Policy path for this resource
	Path *string `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyServiceTag `pulumi:"tags"`
}

type PolicyServiceState struct {
	// Algorithm type service entry
	AlgorithmEntries PolicyServiceAlgorithmEntryArrayInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringPtrInput
	// Ether type service entry
	EtherTypeEntries PolicyServiceEtherTypeEntryArrayInput
	// ICMP type service entry
	IcmpEntries PolicyServiceIcmpEntryArrayInput
	// IGMP type service entry
	IgmpEntries PolicyServiceIgmpEntryArrayInput
	// IP Protocol type service entry
	IpProtocolEntries PolicyServiceIpProtocolEntryArrayInput
	// L4 port set type service entry
	L4PortSetEntries PolicyServiceL4PortSetEntryArrayInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Policy path for this resource
	Path pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyServiceTagArrayInput
}

func (PolicyServiceState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyServiceState)(nil)).Elem()
}

type policyServiceArgs struct {
	// Algorithm type service entry
	AlgorithmEntries []PolicyServiceAlgorithmEntry `pulumi:"algorithmEntries"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Display name for this resource
	DisplayName string `pulumi:"displayName"`
	// Ether type service entry
	EtherTypeEntries []PolicyServiceEtherTypeEntry `pulumi:"etherTypeEntries"`
	// ICMP type service entry
	IcmpEntries []PolicyServiceIcmpEntry `pulumi:"icmpEntries"`
	// IGMP type service entry
	IgmpEntries []PolicyServiceIgmpEntry `pulumi:"igmpEntries"`
	// IP Protocol type service entry
	IpProtocolEntries []PolicyServiceIpProtocolEntry `pulumi:"ipProtocolEntries"`
	// L4 port set type service entry
	L4PortSetEntries []PolicyServiceL4PortSetEntry `pulumi:"l4PortSetEntries"`
	// NSX ID for this resource
	NsxId *string `pulumi:"nsxId"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyServiceTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyService resource.
type PolicyServiceArgs struct {
	// Algorithm type service entry
	AlgorithmEntries PolicyServiceAlgorithmEntryArrayInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Display name for this resource
	DisplayName pulumi.StringInput
	// Ether type service entry
	EtherTypeEntries PolicyServiceEtherTypeEntryArrayInput
	// ICMP type service entry
	IcmpEntries PolicyServiceIcmpEntryArrayInput
	// IGMP type service entry
	IgmpEntries PolicyServiceIgmpEntryArrayInput
	// IP Protocol type service entry
	IpProtocolEntries PolicyServiceIpProtocolEntryArrayInput
	// L4 port set type service entry
	L4PortSetEntries PolicyServiceL4PortSetEntryArrayInput
	// NSX ID for this resource
	NsxId pulumi.StringPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyServiceTagArrayInput
}

func (PolicyServiceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyServiceArgs)(nil)).Elem()
}

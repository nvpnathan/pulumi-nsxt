// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyPredefinedGatewayPolicy struct {
	pulumi.CustomResourceState

	// List of default rules
	DefaultRules PolicyPredefinedGatewayPolicyDefaultRuleArrayOutput `pulumi:"defaultRules"`
	// Description for this resource
	Description pulumi.StringOutput `pulumi:"description"`
	// Path for this Gateway Policy
	Path pulumi.StringOutput `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// List of rules in the section
	Rules PolicyPredefinedGatewayPolicyRuleArrayOutput `pulumi:"rules"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyPredefinedGatewayPolicyTagArrayOutput `pulumi:"tags"`
}

// NewPolicyPredefinedGatewayPolicy registers a new resource with the given unique name, arguments, and options.
func NewPolicyPredefinedGatewayPolicy(ctx *pulumi.Context,
	name string, args *PolicyPredefinedGatewayPolicyArgs, opts ...pulumi.ResourceOption) (*PolicyPredefinedGatewayPolicy, error) {
	if args == nil || args.Path == nil {
		return nil, errors.New("missing required argument 'Path'")
	}
	if args == nil {
		args = &PolicyPredefinedGatewayPolicyArgs{}
	}
	var resource PolicyPredefinedGatewayPolicy
	err := ctx.RegisterResource("nsxt:index/policyPredefinedGatewayPolicy:PolicyPredefinedGatewayPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyPredefinedGatewayPolicy gets an existing PolicyPredefinedGatewayPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyPredefinedGatewayPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyPredefinedGatewayPolicyState, opts ...pulumi.ResourceOption) (*PolicyPredefinedGatewayPolicy, error) {
	var resource PolicyPredefinedGatewayPolicy
	err := ctx.ReadResource("nsxt:index/policyPredefinedGatewayPolicy:PolicyPredefinedGatewayPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyPredefinedGatewayPolicy resources.
type policyPredefinedGatewayPolicyState struct {
	// List of default rules
	DefaultRules []PolicyPredefinedGatewayPolicyDefaultRule `pulumi:"defaultRules"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Path for this Gateway Policy
	Path *string `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// List of rules in the section
	Rules []PolicyPredefinedGatewayPolicyRule `pulumi:"rules"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyPredefinedGatewayPolicyTag `pulumi:"tags"`
}

type PolicyPredefinedGatewayPolicyState struct {
	// List of default rules
	DefaultRules PolicyPredefinedGatewayPolicyDefaultRuleArrayInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Path for this Gateway Policy
	Path pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// List of rules in the section
	Rules PolicyPredefinedGatewayPolicyRuleArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyPredefinedGatewayPolicyTagArrayInput
}

func (PolicyPredefinedGatewayPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyPredefinedGatewayPolicyState)(nil)).Elem()
}

type policyPredefinedGatewayPolicyArgs struct {
	// List of default rules
	DefaultRules []PolicyPredefinedGatewayPolicyDefaultRule `pulumi:"defaultRules"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Path for this Gateway Policy
	Path string `pulumi:"path"`
	// List of rules in the section
	Rules []PolicyPredefinedGatewayPolicyRule `pulumi:"rules"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyPredefinedGatewayPolicyTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyPredefinedGatewayPolicy resource.
type PolicyPredefinedGatewayPolicyArgs struct {
	// List of default rules
	DefaultRules PolicyPredefinedGatewayPolicyDefaultRuleArrayInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Path for this Gateway Policy
	Path pulumi.StringInput
	// List of rules in the section
	Rules PolicyPredefinedGatewayPolicyRuleArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyPredefinedGatewayPolicyTagArrayInput
}

func (PolicyPredefinedGatewayPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyPredefinedGatewayPolicyArgs)(nil)).Elem()
}

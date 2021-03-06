// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyPredefinedSecurityPolicy struct {
	pulumi.CustomResourceState

	// List of default rules
	DefaultRule PolicyPredefinedSecurityPolicyDefaultRuleOutput `pulumi:"defaultRule"`
	// Description for this resource
	Description pulumi.StringOutput `pulumi:"description"`
	// Path for this Security Policy
	Path pulumi.StringOutput `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// List of rules in the section
	Rules PolicyPredefinedSecurityPolicyRuleArrayOutput `pulumi:"rules"`
	// Set of opaque identifiers meaningful to the user
	Tags PolicyPredefinedSecurityPolicyTagArrayOutput `pulumi:"tags"`
}

// NewPolicyPredefinedSecurityPolicy registers a new resource with the given unique name, arguments, and options.
func NewPolicyPredefinedSecurityPolicy(ctx *pulumi.Context,
	name string, args *PolicyPredefinedSecurityPolicyArgs, opts ...pulumi.ResourceOption) (*PolicyPredefinedSecurityPolicy, error) {
	if args == nil || args.Path == nil {
		return nil, errors.New("missing required argument 'Path'")
	}
	if args == nil {
		args = &PolicyPredefinedSecurityPolicyArgs{}
	}
	var resource PolicyPredefinedSecurityPolicy
	err := ctx.RegisterResource("nsxt:index/policyPredefinedSecurityPolicy:PolicyPredefinedSecurityPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyPredefinedSecurityPolicy gets an existing PolicyPredefinedSecurityPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyPredefinedSecurityPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyPredefinedSecurityPolicyState, opts ...pulumi.ResourceOption) (*PolicyPredefinedSecurityPolicy, error) {
	var resource PolicyPredefinedSecurityPolicy
	err := ctx.ReadResource("nsxt:index/policyPredefinedSecurityPolicy:PolicyPredefinedSecurityPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyPredefinedSecurityPolicy resources.
type policyPredefinedSecurityPolicyState struct {
	// List of default rules
	DefaultRule *PolicyPredefinedSecurityPolicyDefaultRule `pulumi:"defaultRule"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Path for this Security Policy
	Path *string `pulumi:"path"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// List of rules in the section
	Rules []PolicyPredefinedSecurityPolicyRule `pulumi:"rules"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyPredefinedSecurityPolicyTag `pulumi:"tags"`
}

type PolicyPredefinedSecurityPolicyState struct {
	// List of default rules
	DefaultRule PolicyPredefinedSecurityPolicyDefaultRulePtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Path for this Security Policy
	Path pulumi.StringPtrInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// List of rules in the section
	Rules PolicyPredefinedSecurityPolicyRuleArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyPredefinedSecurityPolicyTagArrayInput
}

func (PolicyPredefinedSecurityPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyPredefinedSecurityPolicyState)(nil)).Elem()
}

type policyPredefinedSecurityPolicyArgs struct {
	// List of default rules
	DefaultRule *PolicyPredefinedSecurityPolicyDefaultRule `pulumi:"defaultRule"`
	// Description for this resource
	Description *string `pulumi:"description"`
	// Path for this Security Policy
	Path string `pulumi:"path"`
	// List of rules in the section
	Rules []PolicyPredefinedSecurityPolicyRule `pulumi:"rules"`
	// Set of opaque identifiers meaningful to the user
	Tags []PolicyPredefinedSecurityPolicyTag `pulumi:"tags"`
}

// The set of arguments for constructing a PolicyPredefinedSecurityPolicy resource.
type PolicyPredefinedSecurityPolicyArgs struct {
	// List of default rules
	DefaultRule PolicyPredefinedSecurityPolicyDefaultRulePtrInput
	// Description for this resource
	Description pulumi.StringPtrInput
	// Path for this Security Policy
	Path pulumi.StringInput
	// List of rules in the section
	Rules PolicyPredefinedSecurityPolicyRuleArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags PolicyPredefinedSecurityPolicyTagArrayInput
}

func (PolicyPredefinedSecurityPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyPredefinedSecurityPolicyArgs)(nil)).Elem()
}

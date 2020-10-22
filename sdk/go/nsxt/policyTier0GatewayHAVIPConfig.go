// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type PolicyTier0GatewayHAVIPConfig struct {
	pulumi.CustomResourceState

	// Tier0 HA VIP Config
	Configs PolicyTier0GatewayHAVIPConfigConfigArrayOutput `pulumi:"configs"`
	// Id of associated Gateway Locale Service on NSX
	LocaleServiceId pulumi.StringOutput `pulumi:"localeServiceId"`
	// Id of associated Tier0 Gateway on NSX
	Tier0Id pulumi.StringOutput `pulumi:"tier0Id"`
}

// NewPolicyTier0GatewayHAVIPConfig registers a new resource with the given unique name, arguments, and options.
func NewPolicyTier0GatewayHAVIPConfig(ctx *pulumi.Context,
	name string, args *PolicyTier0GatewayHAVIPConfigArgs, opts ...pulumi.ResourceOption) (*PolicyTier0GatewayHAVIPConfig, error) {
	if args == nil || args.Configs == nil {
		return nil, errors.New("missing required argument 'Configs'")
	}
	if args == nil {
		args = &PolicyTier0GatewayHAVIPConfigArgs{}
	}
	var resource PolicyTier0GatewayHAVIPConfig
	err := ctx.RegisterResource("nsxt:index/policyTier0GatewayHAVIPConfig:PolicyTier0GatewayHAVIPConfig", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetPolicyTier0GatewayHAVIPConfig gets an existing PolicyTier0GatewayHAVIPConfig resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetPolicyTier0GatewayHAVIPConfig(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *PolicyTier0GatewayHAVIPConfigState, opts ...pulumi.ResourceOption) (*PolicyTier0GatewayHAVIPConfig, error) {
	var resource PolicyTier0GatewayHAVIPConfig
	err := ctx.ReadResource("nsxt:index/policyTier0GatewayHAVIPConfig:PolicyTier0GatewayHAVIPConfig", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering PolicyTier0GatewayHAVIPConfig resources.
type policyTier0GatewayHAVIPConfigState struct {
	// Tier0 HA VIP Config
	Configs []PolicyTier0GatewayHAVIPConfigConfig `pulumi:"configs"`
	// Id of associated Gateway Locale Service on NSX
	LocaleServiceId *string `pulumi:"localeServiceId"`
	// Id of associated Tier0 Gateway on NSX
	Tier0Id *string `pulumi:"tier0Id"`
}

type PolicyTier0GatewayHAVIPConfigState struct {
	// Tier0 HA VIP Config
	Configs PolicyTier0GatewayHAVIPConfigConfigArrayInput
	// Id of associated Gateway Locale Service on NSX
	LocaleServiceId pulumi.StringPtrInput
	// Id of associated Tier0 Gateway on NSX
	Tier0Id pulumi.StringPtrInput
}

func (PolicyTier0GatewayHAVIPConfigState) ElementType() reflect.Type {
	return reflect.TypeOf((*policyTier0GatewayHAVIPConfigState)(nil)).Elem()
}

type policyTier0GatewayHAVIPConfigArgs struct {
	// Tier0 HA VIP Config
	Configs []PolicyTier0GatewayHAVIPConfigConfig `pulumi:"configs"`
}

// The set of arguments for constructing a PolicyTier0GatewayHAVIPConfig resource.
type PolicyTier0GatewayHAVIPConfigArgs struct {
	// Tier0 HA VIP Config
	Configs PolicyTier0GatewayHAVIPConfigConfigArrayInput
}

func (PolicyTier0GatewayHAVIPConfigArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*policyTier0GatewayHAVIPConfigArgs)(nil)).Elem()
}

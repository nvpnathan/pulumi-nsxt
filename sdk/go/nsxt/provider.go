// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

// The provider type for the nsxt package. By default, resources use package-wide configuration
// settings, however an explicit `Provider` instance may be created and passed during resource
// construction to achieve fine-grained programmatic control over provider settings. See the
// [documentation](https://www.pulumi.com/docs/reference/programming-model/#providers) for more information.
type Provider struct {
	pulumi.ProviderResourceState
}

// NewProvider registers a new resource with the given unique name, arguments, and options.
func NewProvider(ctx *pulumi.Context,
	name string, args *ProviderArgs, opts ...pulumi.ResourceOption) (*Provider, error) {
	if args == nil {
		args = &ProviderArgs{}
	}
	if args.AllowUnverifiedSsl == nil {
		args.AllowUnverifiedSsl = pulumi.BoolPtr(getEnvOrDefault(false, parseEnvBool, "NSXT_ALLOW_UNVERIFIED_SSL").(bool))
	}
	if args.CaFile == nil {
		args.CaFile = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_CA_FILE").(string))
	}
	if args.ClientAuthCertFile == nil {
		args.ClientAuthCertFile = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_CLIENT_AUTH_CERT_FILE").(string))
	}
	if args.ClientAuthKeyFile == nil {
		args.ClientAuthKeyFile = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_CLIENT_AUTH_KEY_FILE").(string))
	}
	if args.EnforcementPoint == nil {
		args.EnforcementPoint = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_POLICY_ENFORCEMENT_POINT").(string))
	}
	if args.GlobalManager == nil {
		args.GlobalManager = pulumi.BoolPtr(getEnvOrDefault(false, parseEnvBool, "NSXT_GLOBAL_MANAGER").(bool))
	}
	if args.Host == nil {
		args.Host = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_MANAGER_HOST").(string))
	}
	if args.MaxRetries == nil {
		args.MaxRetries = pulumi.IntPtr(getEnvOrDefault(0, parseEnvInt, "NSXT_MAX_RETRIES").(int))
	}
	if args.Password == nil {
		args.Password = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_PASSWORD").(string))
	}
	if args.RemoteAuth == nil {
		args.RemoteAuth = pulumi.BoolPtr(getEnvOrDefault(false, parseEnvBool, "NSXT_REMOTE_AUTH").(bool))
	}
	if args.RetryMaxDelay == nil {
		args.RetryMaxDelay = pulumi.IntPtr(getEnvOrDefault(0, parseEnvInt, "NSXT_RETRY_MAX_DELAY").(int))
	}
	if args.RetryMinDelay == nil {
		args.RetryMinDelay = pulumi.IntPtr(getEnvOrDefault(0, parseEnvInt, "NSXT_RETRY_MIN_DELAY").(int))
	}
	if args.ToleratePartialSuccess == nil {
		args.ToleratePartialSuccess = pulumi.BoolPtr(getEnvOrDefault(false, parseEnvBool, "NSXT_TOLERATE_PARTIAL_SUCCESS").(bool))
	}
	if args.Username == nil {
		args.Username = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_USERNAME").(string))
	}
	if args.VmcAuthHost == nil {
		args.VmcAuthHost = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_VMC_AUTH_HOST").(string))
	}
	if args.VmcToken == nil {
		args.VmcToken = pulumi.StringPtr(getEnvOrDefault("", nil, "NSXT_VMC_TOKEN").(string))
	}
	var resource Provider
	err := ctx.RegisterResource("pulumi:providers:nsxt", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

type providerArgs struct {
	AllowUnverifiedSsl *bool   `pulumi:"allowUnverifiedSsl"`
	CaFile             *string `pulumi:"caFile"`
	ClientAuthCertFile *string `pulumi:"clientAuthCertFile"`
	ClientAuthKeyFile  *string `pulumi:"clientAuthKeyFile"`
	// Enforcement Point for NSXT Policy
	EnforcementPoint *string `pulumi:"enforcementPoint"`
	// Is this a policy global manager endpoint
	GlobalManager *bool `pulumi:"globalManager"`
	// The hostname or IP address of the NSX manager.
	Host *string `pulumi:"host"`
	// Maximum number of HTTP client retries
	MaxRetries *int    `pulumi:"maxRetries"`
	Password   *string `pulumi:"password"`
	RemoteAuth *bool   `pulumi:"remoteAuth"`
	// Maximum delay in milliseconds between retries of a request
	RetryMaxDelay *int `pulumi:"retryMaxDelay"`
	// Minimum delay in milliseconds between retries of a request
	RetryMinDelay *int `pulumi:"retryMinDelay"`
	// HTTP replies status codes to retry on
	RetryOnStatusCodes []int `pulumi:"retryOnStatusCodes"`
	// Treat partial success status as success
	ToleratePartialSuccess *bool   `pulumi:"toleratePartialSuccess"`
	Username               *string `pulumi:"username"`
	// URL for VMC authorization service (CSP)
	VmcAuthHost *string `pulumi:"vmcAuthHost"`
	// Long-living API token for VMC authorization
	VmcToken *string `pulumi:"vmcToken"`
}

// The set of arguments for constructing a Provider resource.
type ProviderArgs struct {
	AllowUnverifiedSsl pulumi.BoolPtrInput
	CaFile             pulumi.StringPtrInput
	ClientAuthCertFile pulumi.StringPtrInput
	ClientAuthKeyFile  pulumi.StringPtrInput
	// Enforcement Point for NSXT Policy
	EnforcementPoint pulumi.StringPtrInput
	// Is this a policy global manager endpoint
	GlobalManager pulumi.BoolPtrInput
	// The hostname or IP address of the NSX manager.
	Host pulumi.StringPtrInput
	// Maximum number of HTTP client retries
	MaxRetries pulumi.IntPtrInput
	Password   pulumi.StringPtrInput
	RemoteAuth pulumi.BoolPtrInput
	// Maximum delay in milliseconds between retries of a request
	RetryMaxDelay pulumi.IntPtrInput
	// Minimum delay in milliseconds between retries of a request
	RetryMinDelay pulumi.IntPtrInput
	// HTTP replies status codes to retry on
	RetryOnStatusCodes pulumi.IntArrayInput
	// Treat partial success status as success
	ToleratePartialSuccess pulumi.BoolPtrInput
	Username               pulumi.StringPtrInput
	// URL for VMC authorization service (CSP)
	VmcAuthHost pulumi.StringPtrInput
	// Long-living API token for VMC authorization
	VmcToken pulumi.StringPtrInput
}

func (ProviderArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*providerArgs)(nil)).Elem()
}
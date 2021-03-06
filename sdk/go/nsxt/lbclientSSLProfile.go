// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type LBClientSSLProfile struct {
	pulumi.CustomResourceState

	// Supported SSL cipher list
	Ciphers pulumi.StringArrayOutput `pulumi:"ciphers"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
	// protocols is insecure
	IsSecure pulumi.BoolOutput `pulumi:"isSecure"`
	// Allow server to override the client's preference
	PreferServerCiphers pulumi.BoolPtrOutput `pulumi:"preferServerCiphers"`
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols pulumi.StringArrayOutput `pulumi:"protocols"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Reuse previously negotiated security parameters during handshake
	SessionCacheEnabled pulumi.BoolPtrOutput `pulumi:"sessionCacheEnabled"`
	// For how long the SSL session parameters can be reused
	SessionCacheTimeout pulumi.IntPtrOutput `pulumi:"sessionCacheTimeout"`
	// Set of opaque identifiers meaningful to the user
	Tags LBClientSSLProfileTagArrayOutput `pulumi:"tags"`
}

// NewLBClientSSLProfile registers a new resource with the given unique name, arguments, and options.
func NewLBClientSSLProfile(ctx *pulumi.Context,
	name string, args *LBClientSSLProfileArgs, opts ...pulumi.ResourceOption) (*LBClientSSLProfile, error) {
	if args == nil {
		args = &LBClientSSLProfileArgs{}
	}
	var resource LBClientSSLProfile
	err := ctx.RegisterResource("nsxt:index/lBClientSSLProfile:LBClientSSLProfile", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLBClientSSLProfile gets an existing LBClientSSLProfile resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLBClientSSLProfile(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LBClientSSLProfileState, opts ...pulumi.ResourceOption) (*LBClientSSLProfile, error) {
	var resource LBClientSSLProfile
	err := ctx.ReadResource("nsxt:index/lBClientSSLProfile:LBClientSSLProfile", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LBClientSSLProfile resources.
type lbclientSSLProfileState struct {
	// Supported SSL cipher list
	Ciphers []string `pulumi:"ciphers"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
	// protocols is insecure
	IsSecure *bool `pulumi:"isSecure"`
	// Allow server to override the client's preference
	PreferServerCiphers *bool `pulumi:"preferServerCiphers"`
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols []string `pulumi:"protocols"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Reuse previously negotiated security parameters during handshake
	SessionCacheEnabled *bool `pulumi:"sessionCacheEnabled"`
	// For how long the SSL session parameters can be reused
	SessionCacheTimeout *int `pulumi:"sessionCacheTimeout"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBClientSSLProfileTag `pulumi:"tags"`
}

type LBClientSSLProfileState struct {
	// Supported SSL cipher list
	Ciphers pulumi.StringArrayInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
	// protocols is insecure
	IsSecure pulumi.BoolPtrInput
	// Allow server to override the client's preference
	PreferServerCiphers pulumi.BoolPtrInput
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols pulumi.StringArrayInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Reuse previously negotiated security parameters during handshake
	SessionCacheEnabled pulumi.BoolPtrInput
	// For how long the SSL session parameters can be reused
	SessionCacheTimeout pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBClientSSLProfileTagArrayInput
}

func (LBClientSSLProfileState) ElementType() reflect.Type {
	return reflect.TypeOf((*lbclientSSLProfileState)(nil)).Elem()
}

type lbclientSSLProfileArgs struct {
	// Supported SSL cipher list
	Ciphers []string `pulumi:"ciphers"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// Allow server to override the client's preference
	PreferServerCiphers *bool `pulumi:"preferServerCiphers"`
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols []string `pulumi:"protocols"`
	// Reuse previously negotiated security parameters during handshake
	SessionCacheEnabled *bool `pulumi:"sessionCacheEnabled"`
	// For how long the SSL session parameters can be reused
	SessionCacheTimeout *int `pulumi:"sessionCacheTimeout"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBClientSSLProfileTag `pulumi:"tags"`
}

// The set of arguments for constructing a LBClientSSLProfile resource.
type LBClientSSLProfileArgs struct {
	// Supported SSL cipher list
	Ciphers pulumi.StringArrayInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// Allow server to override the client's preference
	PreferServerCiphers pulumi.BoolPtrInput
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols pulumi.StringArrayInput
	// Reuse previously negotiated security parameters during handshake
	SessionCacheEnabled pulumi.BoolPtrInput
	// For how long the SSL session parameters can be reused
	SessionCacheTimeout pulumi.IntPtrInput
	// Set of opaque identifiers meaningful to the user
	Tags LBClientSSLProfileTagArrayInput
}

func (LBClientSSLProfileArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*lbclientSSLProfileArgs)(nil)).Elem()
}

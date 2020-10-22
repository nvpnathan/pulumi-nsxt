// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"reflect"

	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

type LBHTTPSMonitor struct {
	pulumi.CustomResourceState

	// Verification depth in the server certificate chain
	CertificateChainDepth pulumi.IntPtrOutput `pulumi:"certificateChainDepth"`
	// Supported SSL cipher list
	Ciphers pulumi.StringArrayOutput `pulumi:"ciphers"`
	// client certificate can be specified to support client authentication
	ClientCertificateId pulumi.StringPtrOutput `pulumi:"clientCertificateId"`
	// Description of this resource
	Description pulumi.StringPtrOutput `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Number of consecutive checks that must fail before marking it down
	FallCount pulumi.IntPtrOutput `pulumi:"fallCount"`
	// The frequency at which the system issues the monitor check (in seconds)
	Interval pulumi.IntPtrOutput `pulumi:"interval"`
	// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
	// protocols is insecure
	IsSecure pulumi.BoolOutput `pulumi:"isSecure"`
	// If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
	// supported
	MonitorPort pulumi.StringPtrOutput `pulumi:"monitorPort"`
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols pulumi.StringArrayOutput `pulumi:"protocols"`
	// String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
	RequestBody pulumi.StringPtrOutput `pulumi:"requestBody"`
	// Array of HTTP request headers
	RequestHeaders LBHTTPSMonitorRequestHeaderArrayOutput `pulumi:"requestHeaders"`
	// Health check method for HTTP monitor type
	RequestMethod pulumi.StringPtrOutput `pulumi:"requestMethod"`
	// URL used for HTTP monitor
	RequestUrl pulumi.StringPtrOutput `pulumi:"requestUrl"`
	// HTTP request version
	RequestVersion pulumi.StringPtrOutput `pulumi:"requestVersion"`
	// If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
	// supported), and succeeds only if there is a match
	ResponseBody pulumi.StringPtrOutput `pulumi:"responseBody"`
	// The HTTP response status code should be a valid HTTP status code
	ResponseStatusCodes pulumi.IntArrayOutput `pulumi:"responseStatusCodes"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntOutput `pulumi:"revision"`
	// Number of consecutive checks that must pass before marking it up
	RiseCount pulumi.IntPtrOutput `pulumi:"riseCount"`
	// Server authentication mode
	ServerAuth pulumi.StringPtrOutput `pulumi:"serverAuth"`
	// If server auth type is REQUIRED, server certificate must be signed by one of the CAs
	ServerAuthCaIds pulumi.StringArrayOutput `pulumi:"serverAuthCaIds"`
	// Certificate Revocation List (CRL) to disallow compromised server certificates
	ServerAuthCrlIds pulumi.StringArrayOutput `pulumi:"serverAuthCrlIds"`
	// Set of opaque identifiers meaningful to the user
	Tags LBHTTPSMonitorTagArrayOutput `pulumi:"tags"`
	// Number of seconds the target has to respond to the monitor request
	Timeout pulumi.IntPtrOutput `pulumi:"timeout"`
}

// NewLBHTTPSMonitor registers a new resource with the given unique name, arguments, and options.
func NewLBHTTPSMonitor(ctx *pulumi.Context,
	name string, args *LBHTTPSMonitorArgs, opts ...pulumi.ResourceOption) (*LBHTTPSMonitor, error) {
	if args == nil {
		args = &LBHTTPSMonitorArgs{}
	}
	var resource LBHTTPSMonitor
	err := ctx.RegisterResource("nsxt:index/lBHTTPSMonitor:LBHTTPSMonitor", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLBHTTPSMonitor gets an existing LBHTTPSMonitor resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLBHTTPSMonitor(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LBHTTPSMonitorState, opts ...pulumi.ResourceOption) (*LBHTTPSMonitor, error) {
	var resource LBHTTPSMonitor
	err := ctx.ReadResource("nsxt:index/lBHTTPSMonitor:LBHTTPSMonitor", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LBHTTPSMonitor resources.
type lbhttpsmonitorState struct {
	// Verification depth in the server certificate chain
	CertificateChainDepth *int `pulumi:"certificateChainDepth"`
	// Supported SSL cipher list
	Ciphers []string `pulumi:"ciphers"`
	// client certificate can be specified to support client authentication
	ClientCertificateId *string `pulumi:"clientCertificateId"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// Number of consecutive checks that must fail before marking it down
	FallCount *int `pulumi:"fallCount"`
	// The frequency at which the system issues the monitor check (in seconds)
	Interval *int `pulumi:"interval"`
	// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
	// protocols is insecure
	IsSecure *bool `pulumi:"isSecure"`
	// If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
	// supported
	MonitorPort *string `pulumi:"monitorPort"`
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols []string `pulumi:"protocols"`
	// String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
	RequestBody *string `pulumi:"requestBody"`
	// Array of HTTP request headers
	RequestHeaders []LBHTTPSMonitorRequestHeader `pulumi:"requestHeaders"`
	// Health check method for HTTP monitor type
	RequestMethod *string `pulumi:"requestMethod"`
	// URL used for HTTP monitor
	RequestUrl *string `pulumi:"requestUrl"`
	// HTTP request version
	RequestVersion *string `pulumi:"requestVersion"`
	// If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
	// supported), and succeeds only if there is a match
	ResponseBody *string `pulumi:"responseBody"`
	// The HTTP response status code should be a valid HTTP status code
	ResponseStatusCodes []int `pulumi:"responseStatusCodes"`
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision *int `pulumi:"revision"`
	// Number of consecutive checks that must pass before marking it up
	RiseCount *int `pulumi:"riseCount"`
	// Server authentication mode
	ServerAuth *string `pulumi:"serverAuth"`
	// If server auth type is REQUIRED, server certificate must be signed by one of the CAs
	ServerAuthCaIds []string `pulumi:"serverAuthCaIds"`
	// Certificate Revocation List (CRL) to disallow compromised server certificates
	ServerAuthCrlIds []string `pulumi:"serverAuthCrlIds"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBHTTPSMonitorTag `pulumi:"tags"`
	// Number of seconds the target has to respond to the monitor request
	Timeout *int `pulumi:"timeout"`
}

type LBHTTPSMonitorState struct {
	// Verification depth in the server certificate chain
	CertificateChainDepth pulumi.IntPtrInput
	// Supported SSL cipher list
	Ciphers pulumi.StringArrayInput
	// client certificate can be specified to support client authentication
	ClientCertificateId pulumi.StringPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// Number of consecutive checks that must fail before marking it down
	FallCount pulumi.IntPtrInput
	// The frequency at which the system issues the monitor check (in seconds)
	Interval pulumi.IntPtrInput
	// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
	// protocols is insecure
	IsSecure pulumi.BoolPtrInput
	// If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
	// supported
	MonitorPort pulumi.StringPtrInput
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols pulumi.StringArrayInput
	// String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
	RequestBody pulumi.StringPtrInput
	// Array of HTTP request headers
	RequestHeaders LBHTTPSMonitorRequestHeaderArrayInput
	// Health check method for HTTP monitor type
	RequestMethod pulumi.StringPtrInput
	// URL used for HTTP monitor
	RequestUrl pulumi.StringPtrInput
	// HTTP request version
	RequestVersion pulumi.StringPtrInput
	// If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
	// supported), and succeeds only if there is a match
	ResponseBody pulumi.StringPtrInput
	// The HTTP response status code should be a valid HTTP status code
	ResponseStatusCodes pulumi.IntArrayInput
	// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
	// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
	// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
	Revision pulumi.IntPtrInput
	// Number of consecutive checks that must pass before marking it up
	RiseCount pulumi.IntPtrInput
	// Server authentication mode
	ServerAuth pulumi.StringPtrInput
	// If server auth type is REQUIRED, server certificate must be signed by one of the CAs
	ServerAuthCaIds pulumi.StringArrayInput
	// Certificate Revocation List (CRL) to disallow compromised server certificates
	ServerAuthCrlIds pulumi.StringArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags LBHTTPSMonitorTagArrayInput
	// Number of seconds the target has to respond to the monitor request
	Timeout pulumi.IntPtrInput
}

func (LBHTTPSMonitorState) ElementType() reflect.Type {
	return reflect.TypeOf((*lbhttpsmonitorState)(nil)).Elem()
}

type lbhttpsmonitorArgs struct {
	// Verification depth in the server certificate chain
	CertificateChainDepth *int `pulumi:"certificateChainDepth"`
	// Supported SSL cipher list
	Ciphers []string `pulumi:"ciphers"`
	// client certificate can be specified to support client authentication
	ClientCertificateId *string `pulumi:"clientCertificateId"`
	// Description of this resource
	Description *string `pulumi:"description"`
	// The display name of this resource. Defaults to ID if not set
	DisplayName *string `pulumi:"displayName"`
	// Number of consecutive checks that must fail before marking it down
	FallCount *int `pulumi:"fallCount"`
	// The frequency at which the system issues the monitor check (in seconds)
	Interval *int `pulumi:"interval"`
	// If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
	// supported
	MonitorPort *string `pulumi:"monitorPort"`
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols []string `pulumi:"protocols"`
	// String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
	RequestBody *string `pulumi:"requestBody"`
	// Array of HTTP request headers
	RequestHeaders []LBHTTPSMonitorRequestHeader `pulumi:"requestHeaders"`
	// Health check method for HTTP monitor type
	RequestMethod *string `pulumi:"requestMethod"`
	// URL used for HTTP monitor
	RequestUrl *string `pulumi:"requestUrl"`
	// HTTP request version
	RequestVersion *string `pulumi:"requestVersion"`
	// If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
	// supported), and succeeds only if there is a match
	ResponseBody *string `pulumi:"responseBody"`
	// The HTTP response status code should be a valid HTTP status code
	ResponseStatusCodes []int `pulumi:"responseStatusCodes"`
	// Number of consecutive checks that must pass before marking it up
	RiseCount *int `pulumi:"riseCount"`
	// Server authentication mode
	ServerAuth *string `pulumi:"serverAuth"`
	// If server auth type is REQUIRED, server certificate must be signed by one of the CAs
	ServerAuthCaIds []string `pulumi:"serverAuthCaIds"`
	// Certificate Revocation List (CRL) to disallow compromised server certificates
	ServerAuthCrlIds []string `pulumi:"serverAuthCrlIds"`
	// Set of opaque identifiers meaningful to the user
	Tags []LBHTTPSMonitorTag `pulumi:"tags"`
	// Number of seconds the target has to respond to the monitor request
	Timeout *int `pulumi:"timeout"`
}

// The set of arguments for constructing a LBHTTPSMonitor resource.
type LBHTTPSMonitorArgs struct {
	// Verification depth in the server certificate chain
	CertificateChainDepth pulumi.IntPtrInput
	// Supported SSL cipher list
	Ciphers pulumi.StringArrayInput
	// client certificate can be specified to support client authentication
	ClientCertificateId pulumi.StringPtrInput
	// Description of this resource
	Description pulumi.StringPtrInput
	// The display name of this resource. Defaults to ID if not set
	DisplayName pulumi.StringPtrInput
	// Number of consecutive checks that must fail before marking it down
	FallCount pulumi.IntPtrInput
	// The frequency at which the system issues the monitor check (in seconds)
	Interval pulumi.IntPtrInput
	// If the monitor port is specified, it would override pool member port setting for healthcheck. A port range is not
	// supported
	MonitorPort pulumi.StringPtrInput
	// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
	// disabled by default
	Protocols pulumi.StringArrayInput
	// String to send as HTTP health check request body. Valid only for certain HTTP methods like POST
	RequestBody pulumi.StringPtrInput
	// Array of HTTP request headers
	RequestHeaders LBHTTPSMonitorRequestHeaderArrayInput
	// Health check method for HTTP monitor type
	RequestMethod pulumi.StringPtrInput
	// URL used for HTTP monitor
	RequestUrl pulumi.StringPtrInput
	// HTTP request version
	RequestVersion pulumi.StringPtrInput
	// If HTTP specified, healthcheck HTTP response body is matched against the specified string (regular expressions not
	// supported), and succeeds only if there is a match
	ResponseBody pulumi.StringPtrInput
	// The HTTP response status code should be a valid HTTP status code
	ResponseStatusCodes pulumi.IntArrayInput
	// Number of consecutive checks that must pass before marking it up
	RiseCount pulumi.IntPtrInput
	// Server authentication mode
	ServerAuth pulumi.StringPtrInput
	// If server auth type is REQUIRED, server certificate must be signed by one of the CAs
	ServerAuthCaIds pulumi.StringArrayInput
	// Certificate Revocation List (CRL) to disallow compromised server certificates
	ServerAuthCrlIds pulumi.StringArrayInput
	// Set of opaque identifiers meaningful to the user
	Tags LBHTTPSMonitorTagArrayInput
	// Number of seconds the target has to respond to the monitor request
	Timeout pulumi.IntPtrInput
}

func (LBHTTPSMonitorArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*lbhttpsmonitorArgs)(nil)).Elem()
}

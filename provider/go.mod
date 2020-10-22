module github.com/pulumi/pulumi-nsxt/provider

go 1.14

replace github.com/Azure/go-autorest => github.com/Azure/go-autorest v12.4.3+incompatible

require (
	github.com/hashicorp/terraform-plugin-sdk v1.12.0
	github.com/pulumi/pulumi-terraform-bridge/v2 v2.5.4
	github.com/pulumi/pulumi/sdk/v2 v2.5.1-0.20200701223250-45d2fa95d60b
	github.com/vmware/terraform-provider-nsxt e55314e080b2486761e7ca667f5bb3186a2cad5c
)

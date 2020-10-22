// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package nsxt

import (
	"github.com/pulumi/pulumi/sdk/v2/go/pulumi"
)

func GetCertificate(ctx *pulumi.Context, args *GetCertificateArgs, opts ...pulumi.InvokeOption) (*GetCertificateResult, error) {
	var rv GetCertificateResult
	err := ctx.Invoke("nsxt:index/getCertificate:getCertificate", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCertificate.
type GetCertificateArgs struct {
	Description *string `pulumi:"description"`
	DisplayName *string `pulumi:"displayName"`
	Id          *string `pulumi:"id"`
}

// A collection of values returned by getCertificate.
type GetCertificateResult struct {
	Description string `pulumi:"description"`
	DisplayName string `pulumi:"displayName"`
	Id          string `pulumi:"id"`
}

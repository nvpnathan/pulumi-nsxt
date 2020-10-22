// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetPolicyIPv6DadProfile
    {
        public static Task<GetPolicyIPv6DadProfileResult> InvokeAsync(GetPolicyIPv6DadProfileArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPolicyIPv6DadProfileResult>("nsxt:index/getPolicyIPv6DadProfile:getPolicyIPv6DadProfile", args ?? new GetPolicyIPv6DadProfileArgs(), options.WithVersion());
    }


    public sealed class GetPolicyIPv6DadProfileArgs : Pulumi.InvokeArgs
    {
        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        public GetPolicyIPv6DadProfileArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPolicyIPv6DadProfileResult
    {
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string Id;
        public readonly string Path;

        [OutputConstructor]
        private GetPolicyIPv6DadProfileResult(
            string description,

            string displayName,

            string id,

            string path)
        {
            Description = description;
            DisplayName = displayName;
            Id = id;
            Path = path;
        }
    }
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetPolicyIPPool
    {
        public static Task<GetPolicyIPPoolResult> InvokeAsync(GetPolicyIPPoolArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPolicyIPPoolResult>("nsxt:index/getPolicyIPPool:getPolicyIPPool", args ?? new GetPolicyIPPoolArgs(), options.WithVersion());
    }


    public sealed class GetPolicyIPPoolArgs : Pulumi.InvokeArgs
    {
        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        public GetPolicyIPPoolArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPolicyIPPoolResult
    {
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string Id;
        public readonly string Path;

        [OutputConstructor]
        private GetPolicyIPPoolResult(
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

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetPolicyService
    {
        public static Task<GetPolicyServiceResult> InvokeAsync(GetPolicyServiceArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPolicyServiceResult>("nsxt:index/getPolicyService:getPolicyService", args ?? new GetPolicyServiceArgs(), options.WithVersion());
    }


    public sealed class GetPolicyServiceArgs : Pulumi.InvokeArgs
    {
        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        public GetPolicyServiceArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPolicyServiceResult
    {
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string Id;
        public readonly string Path;

        [OutputConstructor]
        private GetPolicyServiceResult(
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

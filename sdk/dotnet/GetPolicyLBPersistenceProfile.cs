// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetPolicyLBPersistenceProfile
    {
        public static Task<GetPolicyLBPersistenceProfileResult> InvokeAsync(GetPolicyLBPersistenceProfileArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPolicyLBPersistenceProfileResult>("nsxt:index/getPolicyLBPersistenceProfile:getPolicyLBPersistenceProfile", args ?? new GetPolicyLBPersistenceProfileArgs(), options.WithVersion());
    }


    public sealed class GetPolicyLBPersistenceProfileArgs : Pulumi.InvokeArgs
    {
        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        [Input("type")]
        public string? Type { get; set; }

        public GetPolicyLBPersistenceProfileArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPolicyLBPersistenceProfileResult
    {
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string Id;
        public readonly string Path;
        public readonly string? Type;

        [OutputConstructor]
        private GetPolicyLBPersistenceProfileResult(
            string description,

            string displayName,

            string id,

            string path,

            string? type)
        {
            Description = description;
            DisplayName = displayName;
            Id = id;
            Path = path;
            Type = type;
        }
    }
}

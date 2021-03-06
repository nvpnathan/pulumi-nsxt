// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetLogicalTier1Router
    {
        public static Task<GetLogicalTier1RouterResult> InvokeAsync(GetLogicalTier1RouterArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetLogicalTier1RouterResult>("nsxt:index/getLogicalTier1Router:getLogicalTier1Router", args ?? new GetLogicalTier1RouterArgs(), options.WithVersion());
    }


    public sealed class GetLogicalTier1RouterArgs : Pulumi.InvokeArgs
    {
        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("edgeClusterId")]
        public string? EdgeClusterId { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        public GetLogicalTier1RouterArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetLogicalTier1RouterResult
    {
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string EdgeClusterId;
        public readonly string Id;

        [OutputConstructor]
        private GetLogicalTier1RouterResult(
            string description,

            string displayName,

            string edgeClusterId,

            string id)
        {
            Description = description;
            DisplayName = displayName;
            EdgeClusterId = edgeClusterId;
            Id = id;
        }
    }
}

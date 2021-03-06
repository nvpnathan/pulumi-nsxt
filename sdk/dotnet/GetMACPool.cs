// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetMACPool
    {
        public static Task<GetMACPoolResult> InvokeAsync(GetMACPoolArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetMACPoolResult>("nsxt:index/getMACPool:getMACPool", args ?? new GetMACPoolArgs(), options.WithVersion());
    }


    public sealed class GetMACPoolArgs : Pulumi.InvokeArgs
    {
        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        public GetMACPoolArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetMACPoolResult
    {
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string Id;

        [OutputConstructor]
        private GetMACPoolResult(
            string description,

            string displayName,

            string id)
        {
            Description = description;
            DisplayName = displayName;
            Id = id;
        }
    }
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetSwitchingProfile
    {
        public static Task<GetSwitchingProfileResult> InvokeAsync(GetSwitchingProfileArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetSwitchingProfileResult>("nsxt:index/getSwitchingProfile:getSwitchingProfile", args ?? new GetSwitchingProfileArgs(), options.WithVersion());
    }


    public sealed class GetSwitchingProfileArgs : Pulumi.InvokeArgs
    {
        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        public GetSwitchingProfileArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetSwitchingProfileResult
    {
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string Id;
        public readonly string ResourceType;

        [OutputConstructor]
        private GetSwitchingProfileResult(
            string description,

            string displayName,

            string id,

            string resourceType)
        {
            Description = description;
            DisplayName = displayName;
            Id = id;
            ResourceType = resourceType;
        }
    }
}

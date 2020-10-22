// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetPolicyRealizationInfo
    {
        public static Task<GetPolicyRealizationInfoResult> InvokeAsync(GetPolicyRealizationInfoArgs args, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetPolicyRealizationInfoResult>("nsxt:index/getPolicyRealizationInfo:getPolicyRealizationInfo", args ?? new GetPolicyRealizationInfoArgs(), options.WithVersion());
    }


    public sealed class GetPolicyRealizationInfoArgs : Pulumi.InvokeArgs
    {
        [Input("entityType")]
        public string? EntityType { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        [Input("path", required: true)]
        public string Path { get; set; } = null!;

        [Input("sitePath")]
        public string? SitePath { get; set; }

        public GetPolicyRealizationInfoArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetPolicyRealizationInfoResult
    {
        public readonly string EntityType;
        public readonly string Id;
        public readonly string Path;
        public readonly string RealizedId;
        public readonly string? SitePath;
        public readonly string State;

        [OutputConstructor]
        private GetPolicyRealizationInfoResult(
            string entityType,

            string id,

            string path,

            string realizedId,

            string? sitePath,

            string state)
        {
            EntityType = entityType;
            Id = id;
            Path = path;
            RealizedId = realizedId;
            SitePath = sitePath;
            State = state;
        }
    }
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public static class GetEdgeCluster
    {
        public static Task<GetEdgeClusterResult> InvokeAsync(GetEdgeClusterArgs? args = null, InvokeOptions? options = null)
            => Pulumi.Deployment.Instance.InvokeAsync<GetEdgeClusterResult>("nsxt:index/getEdgeCluster:getEdgeCluster", args ?? new GetEdgeClusterArgs(), options.WithVersion());
    }


    public sealed class GetEdgeClusterArgs : Pulumi.InvokeArgs
    {
        [Input("deploymentType")]
        public string? DeploymentType { get; set; }

        [Input("description")]
        public string? Description { get; set; }

        [Input("displayName")]
        public string? DisplayName { get; set; }

        [Input("id")]
        public string? Id { get; set; }

        [Input("memberNodeType")]
        public string? MemberNodeType { get; set; }

        public GetEdgeClusterArgs()
        {
        }
    }


    [OutputType]
    public sealed class GetEdgeClusterResult
    {
        public readonly string DeploymentType;
        public readonly string Description;
        public readonly string DisplayName;
        public readonly string Id;
        public readonly string MemberNodeType;

        [OutputConstructor]
        private GetEdgeClusterResult(
            string deploymentType,

            string description,

            string displayName,

            string id,

            string memberNodeType)
        {
            DeploymentType = deploymentType;
            Description = description;
            DisplayName = displayName;
            Id = id;
            MemberNodeType = memberNodeType;
        }
    }
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Outputs
{

    [OutputType]
    public sealed class PolicyTier1GatewayLocaleService
    {
        public readonly string EdgeClusterPath;
        public readonly string? Path;
        public readonly ImmutableArray<string> PreferredEdgePaths;
        public readonly int? Revision;

        [OutputConstructor]
        private PolicyTier1GatewayLocaleService(
            string edgeClusterPath,

            string? path,

            ImmutableArray<string> preferredEdgePaths,

            int? revision)
        {
            EdgeClusterPath = edgeClusterPath;
            Path = path;
            PreferredEdgePaths = preferredEdgePaths;
            Revision = revision;
        }
    }
}
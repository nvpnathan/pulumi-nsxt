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
    public sealed class PolicyTier0GatewayVrfConfigRouteTarget
    {
        public readonly string? AddressFamily;
        public readonly bool? AutoMode;
        public readonly ImmutableArray<string> ExportTargets;
        public readonly ImmutableArray<string> ImportTargets;

        [OutputConstructor]
        private PolicyTier0GatewayVrfConfigRouteTarget(
            string? addressFamily,

            bool? autoMode,

            ImmutableArray<string> exportTargets,

            ImmutableArray<string> importTargets)
        {
            AddressFamily = addressFamily;
            AutoMode = autoMode;
            ExportTargets = exportTargets;
            ImportTargets = importTargets;
        }
    }
}

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
    public sealed class StaticRouteNextHop
    {
        public readonly int? AdministrativeDistance;
        public readonly bool? BfdEnabled;
        public readonly string? BlackholeAction;
        public readonly string? IpAddress;
        public readonly string? LogicalRouterPortId;

        [OutputConstructor]
        private StaticRouteNextHop(
            int? administrativeDistance,

            bool? bfdEnabled,

            string? blackholeAction,

            string? ipAddress,

            string? logicalRouterPortId)
        {
            AdministrativeDistance = administrativeDistance;
            BfdEnabled = bfdEnabled;
            BlackholeAction = blackholeAction;
            IpAddress = ipAddress;
            LogicalRouterPortId = logicalRouterPortId;
        }
    }
}

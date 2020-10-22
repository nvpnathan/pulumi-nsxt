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
    public sealed class LBPoolMemberGroup
    {
        public readonly Outputs.LBPoolMemberGroupGroupingObject GroupingObject;
        public readonly string? IpVersionFilter;
        public readonly bool? LimitIpListSize;
        public readonly int? MaxIpListSize;
        public readonly int? Port;

        [OutputConstructor]
        private LBPoolMemberGroup(
            Outputs.LBPoolMemberGroupGroupingObject groupingObject,

            string? ipVersionFilter,

            bool? limitIpListSize,

            int? maxIpListSize,

            int? port)
        {
            GroupingObject = groupingObject;
            IpVersionFilter = ipVersionFilter;
            LimitIpListSize = limitIpListSize;
            MaxIpListSize = maxIpListSize;
            Port = port;
        }
    }
}

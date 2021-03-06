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
    public sealed class PolicySegmentSubnetDhcpV6Config
    {
        public readonly ImmutableArray<string> DnsServers;
        public readonly ImmutableArray<string> DomainNames;
        public readonly ImmutableArray<Outputs.PolicySegmentSubnetDhcpV6ConfigExcludedRange> ExcludedRanges;
        public readonly int? LeaseTime;
        public readonly int? PreferredTime;
        public readonly string? ServerAddress;
        public readonly ImmutableArray<string> SntpServers;

        [OutputConstructor]
        private PolicySegmentSubnetDhcpV6Config(
            ImmutableArray<string> dnsServers,

            ImmutableArray<string> domainNames,

            ImmutableArray<Outputs.PolicySegmentSubnetDhcpV6ConfigExcludedRange> excludedRanges,

            int? leaseTime,

            int? preferredTime,

            string? serverAddress,

            ImmutableArray<string> sntpServers)
        {
            DnsServers = dnsServers;
            DomainNames = domainNames;
            ExcludedRanges = excludedRanges;
            LeaseTime = leaseTime;
            PreferredTime = preferredTime;
            ServerAddress = serverAddress;
            SntpServers = sntpServers;
        }
    }
}

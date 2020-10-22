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
    public sealed class PolicyVlanSegmentSubnetDhcpV4Config
    {
        public readonly ImmutableArray<Outputs.PolicyVlanSegmentSubnetDhcpV4ConfigDhcpGenericOption> DhcpGenericOptions;
        public readonly ImmutableArray<Outputs.PolicyVlanSegmentSubnetDhcpV4ConfigDhcpOption121> DhcpOption121s;
        public readonly ImmutableArray<string> DnsServers;
        public readonly int? LeaseTime;
        public readonly string? ServerAddress;

        [OutputConstructor]
        private PolicyVlanSegmentSubnetDhcpV4Config(
            ImmutableArray<Outputs.PolicyVlanSegmentSubnetDhcpV4ConfigDhcpGenericOption> dhcpGenericOptions,

            ImmutableArray<Outputs.PolicyVlanSegmentSubnetDhcpV4ConfigDhcpOption121> dhcpOption121s,

            ImmutableArray<string> dnsServers,

            int? leaseTime,

            string? serverAddress)
        {
            DhcpGenericOptions = dhcpGenericOptions;
            DhcpOption121s = dhcpOption121s;
            DnsServers = dnsServers;
            LeaseTime = leaseTime;
            ServerAddress = serverAddress;
        }
    }
}

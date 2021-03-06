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
    public sealed class IPPoolSubnet
    {
        public readonly ImmutableArray<string> AllocationRanges;
        public readonly string Cidr;
        public readonly ImmutableArray<string> DnsNameservers;
        public readonly string? DnsSuffix;
        public readonly string? GatewayIp;

        [OutputConstructor]
        private IPPoolSubnet(
            ImmutableArray<string> allocationRanges,

            string cidr,

            ImmutableArray<string> dnsNameservers,

            string? dnsSuffix,

            string? gatewayIp)
        {
            AllocationRanges = allocationRanges;
            Cidr = cidr;
            DnsNameservers = dnsNameservers;
            DnsSuffix = dnsSuffix;
            GatewayIp = gatewayIp;
        }
    }
}

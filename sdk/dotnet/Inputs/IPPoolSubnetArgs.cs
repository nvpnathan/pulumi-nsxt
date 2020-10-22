// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class IPPoolSubnetArgs : Pulumi.ResourceArgs
    {
        [Input("allocationRanges", required: true)]
        private InputList<string>? _allocationRanges;
        public InputList<string> AllocationRanges
        {
            get => _allocationRanges ?? (_allocationRanges = new InputList<string>());
            set => _allocationRanges = value;
        }

        [Input("cidr", required: true)]
        public Input<string> Cidr { get; set; } = null!;

        [Input("dnsNameservers")]
        private InputList<string>? _dnsNameservers;
        public InputList<string> DnsNameservers
        {
            get => _dnsNameservers ?? (_dnsNameservers = new InputList<string>());
            set => _dnsNameservers = value;
        }

        [Input("dnsSuffix")]
        public Input<string>? DnsSuffix { get; set; }

        [Input("gatewayIp")]
        public Input<string>? GatewayIp { get; set; }

        public IPPoolSubnetArgs()
        {
        }
    }
}

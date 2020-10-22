// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicySegmentSubnetDhcpV6ConfigGetArgs : Pulumi.ResourceArgs
    {
        [Input("dnsServers")]
        private InputList<string>? _dnsServers;
        public InputList<string> DnsServers
        {
            get => _dnsServers ?? (_dnsServers = new InputList<string>());
            set => _dnsServers = value;
        }

        [Input("domainNames")]
        private InputList<string>? _domainNames;
        public InputList<string> DomainNames
        {
            get => _domainNames ?? (_domainNames = new InputList<string>());
            set => _domainNames = value;
        }

        [Input("excludedRanges")]
        private InputList<Inputs.PolicySegmentSubnetDhcpV6ConfigExcludedRangeGetArgs>? _excludedRanges;
        public InputList<Inputs.PolicySegmentSubnetDhcpV6ConfigExcludedRangeGetArgs> ExcludedRanges
        {
            get => _excludedRanges ?? (_excludedRanges = new InputList<Inputs.PolicySegmentSubnetDhcpV6ConfigExcludedRangeGetArgs>());
            set => _excludedRanges = value;
        }

        [Input("leaseTime")]
        public Input<int>? LeaseTime { get; set; }

        [Input("preferredTime")]
        public Input<int>? PreferredTime { get; set; }

        [Input("serverAddress")]
        public Input<string>? ServerAddress { get; set; }

        [Input("sntpServers")]
        private InputList<string>? _sntpServers;
        public InputList<string> SntpServers
        {
            get => _sntpServers ?? (_sntpServers = new InputList<string>());
            set => _sntpServers = value;
        }

        public PolicySegmentSubnetDhcpV6ConfigGetArgs()
        {
        }
    }
}
// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicyVlanSegment : Pulumi.CustomResource
    {
        /// <summary>
        /// Advanced segment configuration
        /// </summary>
        [Output("advancedConfig")]
        public Output<Outputs.PolicyVlanSegmentAdvancedConfig?> AdvancedConfig { get; private set; } = null!;

        /// <summary>
        /// Description for this resource
        /// </summary>
        [Output("description")]
        public Output<string?> Description { get; private set; } = null!;

        /// <summary>
        /// Policy path to DHCP server or relay configuration to use for subnets configured on this segment
        /// </summary>
        [Output("dhcpConfigPath")]
        public Output<string?> DhcpConfigPath { get; private set; } = null!;

        /// <summary>
        /// IP and MAC discovery profiles for this segment
        /// </summary>
        [Output("discoveryProfile")]
        public Output<Outputs.PolicyVlanSegmentDiscoveryProfile?> DiscoveryProfile { get; private set; } = null!;

        /// <summary>
        /// Display name for this resource
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// DNS domain names
        /// </summary>
        [Output("domainName")]
        public Output<string?> DomainName { get; private set; } = null!;

        /// <summary>
        /// Configuration for extending Segment through L2 VPN
        /// </summary>
        [Output("l2Extension")]
        public Output<Outputs.PolicyVlanSegmentL2Extension?> L2Extension { get; private set; } = null!;

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Output("nsxId")]
        public Output<string> NsxId { get; private set; } = null!;

        /// <summary>
        /// Policy path for this resource
        /// </summary>
        [Output("path")]
        public Output<string> Path { get; private set; } = null!;

        /// <summary>
        /// QoS profiles for this segment
        /// </summary>
        [Output("qosProfile")]
        public Output<Outputs.PolicyVlanSegmentQosProfile?> QosProfile { get; private set; } = null!;

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Output("revision")]
        public Output<int> Revision { get; private set; } = null!;

        /// <summary>
        /// Security profiles for this segment
        /// </summary>
        [Output("securityProfile")]
        public Output<Outputs.PolicyVlanSegmentSecurityProfile?> SecurityProfile { get; private set; } = null!;

        /// <summary>
        /// Subnet configuration with at most 1 IPv4 CIDR and multiple IPv6 CIDRs
        /// </summary>
        [Output("subnets")]
        public Output<ImmutableArray<Outputs.PolicyVlanSegmentSubnet>> Subnets { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.PolicyVlanSegmentTag>> Tags { get; private set; } = null!;

        /// <summary>
        /// Policy path to the transport zone
        /// </summary>
        [Output("transportZonePath")]
        public Output<string> TransportZonePath { get; private set; } = null!;

        /// <summary>
        /// VLAN IDs for VLAN backed Segment
        /// </summary>
        [Output("vlanIds")]
        public Output<ImmutableArray<string>> VlanIds { get; private set; } = null!;


        /// <summary>
        /// Create a PolicyVlanSegment resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicyVlanSegment(string name, PolicyVlanSegmentArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policyVlanSegment:PolicyVlanSegment", name, args ?? new PolicyVlanSegmentArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicyVlanSegment(string name, Input<string> id, PolicyVlanSegmentState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policyVlanSegment:PolicyVlanSegment", name, state, MakeResourceOptions(options, id))
        {
        }

        private static CustomResourceOptions MakeResourceOptions(CustomResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new CustomResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = CustomResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
        /// <summary>
        /// Get an existing PolicyVlanSegment resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicyVlanSegment Get(string name, Input<string> id, PolicyVlanSegmentState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicyVlanSegment(name, id, state, options);
        }
    }

    public sealed class PolicyVlanSegmentArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Advanced segment configuration
        /// </summary>
        [Input("advancedConfig")]
        public Input<Inputs.PolicyVlanSegmentAdvancedConfigArgs>? AdvancedConfig { get; set; }

        /// <summary>
        /// Description for this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Policy path to DHCP server or relay configuration to use for subnets configured on this segment
        /// </summary>
        [Input("dhcpConfigPath")]
        public Input<string>? DhcpConfigPath { get; set; }

        /// <summary>
        /// IP and MAC discovery profiles for this segment
        /// </summary>
        [Input("discoveryProfile")]
        public Input<Inputs.PolicyVlanSegmentDiscoveryProfileArgs>? DiscoveryProfile { get; set; }

        /// <summary>
        /// Display name for this resource
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// DNS domain names
        /// </summary>
        [Input("domainName")]
        public Input<string>? DomainName { get; set; }

        /// <summary>
        /// Configuration for extending Segment through L2 VPN
        /// </summary>
        [Input("l2Extension")]
        public Input<Inputs.PolicyVlanSegmentL2ExtensionArgs>? L2Extension { get; set; }

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        /// <summary>
        /// QoS profiles for this segment
        /// </summary>
        [Input("qosProfile")]
        public Input<Inputs.PolicyVlanSegmentQosProfileArgs>? QosProfile { get; set; }

        /// <summary>
        /// Security profiles for this segment
        /// </summary>
        [Input("securityProfile")]
        public Input<Inputs.PolicyVlanSegmentSecurityProfileArgs>? SecurityProfile { get; set; }

        [Input("subnets")]
        private InputList<Inputs.PolicyVlanSegmentSubnetArgs>? _subnets;

        /// <summary>
        /// Subnet configuration with at most 1 IPv4 CIDR and multiple IPv6 CIDRs
        /// </summary>
        public InputList<Inputs.PolicyVlanSegmentSubnetArgs> Subnets
        {
            get => _subnets ?? (_subnets = new InputList<Inputs.PolicyVlanSegmentSubnetArgs>());
            set => _subnets = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyVlanSegmentTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyVlanSegmentTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyVlanSegmentTagArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// Policy path to the transport zone
        /// </summary>
        [Input("transportZonePath", required: true)]
        public Input<string> TransportZonePath { get; set; } = null!;

        [Input("vlanIds", required: true)]
        private InputList<string>? _vlanIds;

        /// <summary>
        /// VLAN IDs for VLAN backed Segment
        /// </summary>
        public InputList<string> VlanIds
        {
            get => _vlanIds ?? (_vlanIds = new InputList<string>());
            set => _vlanIds = value;
        }

        public PolicyVlanSegmentArgs()
        {
        }
    }

    public sealed class PolicyVlanSegmentState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Advanced segment configuration
        /// </summary>
        [Input("advancedConfig")]
        public Input<Inputs.PolicyVlanSegmentAdvancedConfigGetArgs>? AdvancedConfig { get; set; }

        /// <summary>
        /// Description for this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Policy path to DHCP server or relay configuration to use for subnets configured on this segment
        /// </summary>
        [Input("dhcpConfigPath")]
        public Input<string>? DhcpConfigPath { get; set; }

        /// <summary>
        /// IP and MAC discovery profiles for this segment
        /// </summary>
        [Input("discoveryProfile")]
        public Input<Inputs.PolicyVlanSegmentDiscoveryProfileGetArgs>? DiscoveryProfile { get; set; }

        /// <summary>
        /// Display name for this resource
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// DNS domain names
        /// </summary>
        [Input("domainName")]
        public Input<string>? DomainName { get; set; }

        /// <summary>
        /// Configuration for extending Segment through L2 VPN
        /// </summary>
        [Input("l2Extension")]
        public Input<Inputs.PolicyVlanSegmentL2ExtensionGetArgs>? L2Extension { get; set; }

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        /// <summary>
        /// Policy path for this resource
        /// </summary>
        [Input("path")]
        public Input<string>? Path { get; set; }

        /// <summary>
        /// QoS profiles for this segment
        /// </summary>
        [Input("qosProfile")]
        public Input<Inputs.PolicyVlanSegmentQosProfileGetArgs>? QosProfile { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        /// <summary>
        /// Security profiles for this segment
        /// </summary>
        [Input("securityProfile")]
        public Input<Inputs.PolicyVlanSegmentSecurityProfileGetArgs>? SecurityProfile { get; set; }

        [Input("subnets")]
        private InputList<Inputs.PolicyVlanSegmentSubnetGetArgs>? _subnets;

        /// <summary>
        /// Subnet configuration with at most 1 IPv4 CIDR and multiple IPv6 CIDRs
        /// </summary>
        public InputList<Inputs.PolicyVlanSegmentSubnetGetArgs> Subnets
        {
            get => _subnets ?? (_subnets = new InputList<Inputs.PolicyVlanSegmentSubnetGetArgs>());
            set => _subnets = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyVlanSegmentTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyVlanSegmentTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyVlanSegmentTagGetArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// Policy path to the transport zone
        /// </summary>
        [Input("transportZonePath")]
        public Input<string>? TransportZonePath { get; set; }

        [Input("vlanIds")]
        private InputList<string>? _vlanIds;

        /// <summary>
        /// VLAN IDs for VLAN backed Segment
        /// </summary>
        public InputList<string> VlanIds
        {
            get => _vlanIds ?? (_vlanIds = new InputList<string>());
            set => _vlanIds = value;
        }

        public PolicyVlanSegmentState()
        {
        }
    }
}

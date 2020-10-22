// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicyBGPNeighbor : Pulumi.CustomResource
    {
        /// <summary>
        /// Flag to enable allowas_in option for BGP neighbor
        /// </summary>
        [Output("allowAsIn")]
        public Output<bool?> AllowAsIn { get; private set; } = null!;

        /// <summary>
        /// BFD configuration for failure detection
        /// </summary>
        [Output("bfdConfig")]
        public Output<Outputs.PolicyBGPNeighborBfdConfig?> BfdConfig { get; private set; } = null!;

        /// <summary>
        /// Policy path to the BGP for this neighbor
        /// </summary>
        [Output("bgpPath")]
        public Output<string> BgpPath { get; private set; } = null!;

        /// <summary>
        /// Description for this resource
        /// </summary>
        [Output("description")]
        public Output<string?> Description { get; private set; } = null!;

        /// <summary>
        /// Display name for this resource
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// BGP Graceful Restart Configuration Mode
        /// </summary>
        [Output("gracefulRestartMode")]
        public Output<string?> GracefulRestartMode { get; private set; } = null!;

        /// <summary>
        /// Wait time in seconds before declaring peer dead
        /// </summary>
        [Output("holdDownTime")]
        public Output<int?> HoldDownTime { get; private set; } = null!;

        /// <summary>
        /// Interval between keep alive messages sent to peer
        /// </summary>
        [Output("keepAliveTime")]
        public Output<int?> KeepAliveTime { get; private set; } = null!;

        /// <summary>
        /// Maximum number of hops allowed to reach BGP neighbor
        /// </summary>
        [Output("maximumHopLimit")]
        public Output<int?> MaximumHopLimit { get; private set; } = null!;

        /// <summary>
        /// Neighbor IP Address
        /// </summary>
        [Output("neighborAddress")]
        public Output<string> NeighborAddress { get; private set; } = null!;

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Output("nsxId")]
        public Output<string> NsxId { get; private set; } = null!;

        /// <summary>
        /// Password for BGP neighbor authentication
        /// </summary>
        [Output("password")]
        public Output<string?> Password { get; private set; } = null!;

        /// <summary>
        /// Policy path for this resource
        /// </summary>
        [Output("path")]
        public Output<string> Path { get; private set; } = null!;

        /// <summary>
        /// ASN of the neighbor in ASPLAIN or ASDOT Format
        /// </summary>
        [Output("remoteAsNum")]
        public Output<string> RemoteAsNum { get; private set; } = null!;

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Output("revision")]
        public Output<int> Revision { get; private set; } = null!;

        /// <summary>
        /// Enable address families and route filtering in each direction
        /// </summary>
        [Output("routeFilterings")]
        public Output<ImmutableArray<Outputs.PolicyBGPNeighborRouteFiltering>> RouteFilterings { get; private set; } = null!;

        /// <summary>
        /// Source IP Addresses for BGP peering
        /// </summary>
        [Output("sourceAddresses")]
        public Output<ImmutableArray<string>> SourceAddresses { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.PolicyBGPNeighborTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a PolicyBGPNeighbor resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicyBGPNeighbor(string name, PolicyBGPNeighborArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policyBGPNeighbor:PolicyBGPNeighbor", name, args ?? new PolicyBGPNeighborArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicyBGPNeighbor(string name, Input<string> id, PolicyBGPNeighborState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policyBGPNeighbor:PolicyBGPNeighbor", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PolicyBGPNeighbor resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicyBGPNeighbor Get(string name, Input<string> id, PolicyBGPNeighborState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicyBGPNeighbor(name, id, state, options);
        }
    }

    public sealed class PolicyBGPNeighborArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Flag to enable allowas_in option for BGP neighbor
        /// </summary>
        [Input("allowAsIn")]
        public Input<bool>? AllowAsIn { get; set; }

        /// <summary>
        /// BFD configuration for failure detection
        /// </summary>
        [Input("bfdConfig")]
        public Input<Inputs.PolicyBGPNeighborBfdConfigArgs>? BfdConfig { get; set; }

        /// <summary>
        /// Policy path to the BGP for this neighbor
        /// </summary>
        [Input("bgpPath", required: true)]
        public Input<string> BgpPath { get; set; } = null!;

        /// <summary>
        /// Description for this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Display name for this resource
        /// </summary>
        [Input("displayName", required: true)]
        public Input<string> DisplayName { get; set; } = null!;

        /// <summary>
        /// BGP Graceful Restart Configuration Mode
        /// </summary>
        [Input("gracefulRestartMode")]
        public Input<string>? GracefulRestartMode { get; set; }

        /// <summary>
        /// Wait time in seconds before declaring peer dead
        /// </summary>
        [Input("holdDownTime")]
        public Input<int>? HoldDownTime { get; set; }

        /// <summary>
        /// Interval between keep alive messages sent to peer
        /// </summary>
        [Input("keepAliveTime")]
        public Input<int>? KeepAliveTime { get; set; }

        /// <summary>
        /// Maximum number of hops allowed to reach BGP neighbor
        /// </summary>
        [Input("maximumHopLimit")]
        public Input<int>? MaximumHopLimit { get; set; }

        /// <summary>
        /// Neighbor IP Address
        /// </summary>
        [Input("neighborAddress", required: true)]
        public Input<string> NeighborAddress { get; set; } = null!;

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        /// <summary>
        /// Password for BGP neighbor authentication
        /// </summary>
        [Input("password")]
        public Input<string>? Password { get; set; }

        /// <summary>
        /// ASN of the neighbor in ASPLAIN or ASDOT Format
        /// </summary>
        [Input("remoteAsNum", required: true)]
        public Input<string> RemoteAsNum { get; set; } = null!;

        [Input("routeFilterings")]
        private InputList<Inputs.PolicyBGPNeighborRouteFilteringArgs>? _routeFilterings;

        /// <summary>
        /// Enable address families and route filtering in each direction
        /// </summary>
        public InputList<Inputs.PolicyBGPNeighborRouteFilteringArgs> RouteFilterings
        {
            get => _routeFilterings ?? (_routeFilterings = new InputList<Inputs.PolicyBGPNeighborRouteFilteringArgs>());
            set => _routeFilterings = value;
        }

        [Input("sourceAddresses")]
        private InputList<string>? _sourceAddresses;

        /// <summary>
        /// Source IP Addresses for BGP peering
        /// </summary>
        public InputList<string> SourceAddresses
        {
            get => _sourceAddresses ?? (_sourceAddresses = new InputList<string>());
            set => _sourceAddresses = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyBGPNeighborTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyBGPNeighborTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyBGPNeighborTagArgs>());
            set => _tags = value;
        }

        public PolicyBGPNeighborArgs()
        {
        }
    }

    public sealed class PolicyBGPNeighborState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Flag to enable allowas_in option for BGP neighbor
        /// </summary>
        [Input("allowAsIn")]
        public Input<bool>? AllowAsIn { get; set; }

        /// <summary>
        /// BFD configuration for failure detection
        /// </summary>
        [Input("bfdConfig")]
        public Input<Inputs.PolicyBGPNeighborBfdConfigGetArgs>? BfdConfig { get; set; }

        /// <summary>
        /// Policy path to the BGP for this neighbor
        /// </summary>
        [Input("bgpPath")]
        public Input<string>? BgpPath { get; set; }

        /// <summary>
        /// Description for this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Display name for this resource
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// BGP Graceful Restart Configuration Mode
        /// </summary>
        [Input("gracefulRestartMode")]
        public Input<string>? GracefulRestartMode { get; set; }

        /// <summary>
        /// Wait time in seconds before declaring peer dead
        /// </summary>
        [Input("holdDownTime")]
        public Input<int>? HoldDownTime { get; set; }

        /// <summary>
        /// Interval between keep alive messages sent to peer
        /// </summary>
        [Input("keepAliveTime")]
        public Input<int>? KeepAliveTime { get; set; }

        /// <summary>
        /// Maximum number of hops allowed to reach BGP neighbor
        /// </summary>
        [Input("maximumHopLimit")]
        public Input<int>? MaximumHopLimit { get; set; }

        /// <summary>
        /// Neighbor IP Address
        /// </summary>
        [Input("neighborAddress")]
        public Input<string>? NeighborAddress { get; set; }

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        /// <summary>
        /// Password for BGP neighbor authentication
        /// </summary>
        [Input("password")]
        public Input<string>? Password { get; set; }

        /// <summary>
        /// Policy path for this resource
        /// </summary>
        [Input("path")]
        public Input<string>? Path { get; set; }

        /// <summary>
        /// ASN of the neighbor in ASPLAIN or ASDOT Format
        /// </summary>
        [Input("remoteAsNum")]
        public Input<string>? RemoteAsNum { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("routeFilterings")]
        private InputList<Inputs.PolicyBGPNeighborRouteFilteringGetArgs>? _routeFilterings;

        /// <summary>
        /// Enable address families and route filtering in each direction
        /// </summary>
        public InputList<Inputs.PolicyBGPNeighborRouteFilteringGetArgs> RouteFilterings
        {
            get => _routeFilterings ?? (_routeFilterings = new InputList<Inputs.PolicyBGPNeighborRouteFilteringGetArgs>());
            set => _routeFilterings = value;
        }

        [Input("sourceAddresses")]
        private InputList<string>? _sourceAddresses;

        /// <summary>
        /// Source IP Addresses for BGP peering
        /// </summary>
        public InputList<string> SourceAddresses
        {
            get => _sourceAddresses ?? (_sourceAddresses = new InputList<string>());
            set => _sourceAddresses = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyBGPNeighborTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyBGPNeighborTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyBGPNeighborTagGetArgs>());
            set => _tags = value;
        }

        public PolicyBGPNeighborState()
        {
        }
    }
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class SwitchSecuritySwitchingProfile : Pulumi.CustomResource
    {
        /// <summary>
        /// Indicates whether DHCP client blocking is enabled
        /// </summary>
        [Output("blockClientDhcp")]
        public Output<bool?> BlockClientDhcp { get; private set; } = null!;

        /// <summary>
        /// Block all traffic except IP/(G)ARP/BPDU
        /// </summary>
        [Output("blockNonIp")]
        public Output<bool?> BlockNonIp { get; private set; } = null!;

        /// <summary>
        /// Indicates whether DHCP server blocking is enabled
        /// </summary>
        [Output("blockServerDhcp")]
        public Output<bool?> BlockServerDhcp { get; private set; } = null!;

        /// <summary>
        /// Indicates whether BPDU filter is enabled
        /// </summary>
        [Output("bpduFilterEnabled")]
        public Output<bool?> BpduFilterEnabled { get; private set; } = null!;

        /// <summary>
        /// Set of allowed MAC addresses to be excluded from BPDU filtering
        /// </summary>
        [Output("bpduFilterWhitelists")]
        public Output<ImmutableArray<string>> BpduFilterWhitelists { get; private set; } = null!;

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Output("description")]
        public Output<string?> Description { get; private set; } = null!;

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        [Output("rateLimits")]
        public Output<Outputs.SwitchSecuritySwitchingProfileRateLimits?> RateLimits { get; private set; } = null!;

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Output("revision")]
        public Output<int> Revision { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.SwitchSecuritySwitchingProfileTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a SwitchSecuritySwitchingProfile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public SwitchSecuritySwitchingProfile(string name, SwitchSecuritySwitchingProfileArgs? args = null, CustomResourceOptions? options = null)
            : base("nsxt:index/switchSecuritySwitchingProfile:SwitchSecuritySwitchingProfile", name, args ?? new SwitchSecuritySwitchingProfileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private SwitchSecuritySwitchingProfile(string name, Input<string> id, SwitchSecuritySwitchingProfileState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/switchSecuritySwitchingProfile:SwitchSecuritySwitchingProfile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing SwitchSecuritySwitchingProfile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static SwitchSecuritySwitchingProfile Get(string name, Input<string> id, SwitchSecuritySwitchingProfileState? state = null, CustomResourceOptions? options = null)
        {
            return new SwitchSecuritySwitchingProfile(name, id, state, options);
        }
    }

    public sealed class SwitchSecuritySwitchingProfileArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Indicates whether DHCP client blocking is enabled
        /// </summary>
        [Input("blockClientDhcp")]
        public Input<bool>? BlockClientDhcp { get; set; }

        /// <summary>
        /// Block all traffic except IP/(G)ARP/BPDU
        /// </summary>
        [Input("blockNonIp")]
        public Input<bool>? BlockNonIp { get; set; }

        /// <summary>
        /// Indicates whether DHCP server blocking is enabled
        /// </summary>
        [Input("blockServerDhcp")]
        public Input<bool>? BlockServerDhcp { get; set; }

        /// <summary>
        /// Indicates whether BPDU filter is enabled
        /// </summary>
        [Input("bpduFilterEnabled")]
        public Input<bool>? BpduFilterEnabled { get; set; }

        [Input("bpduFilterWhitelists")]
        private InputList<string>? _bpduFilterWhitelists;

        /// <summary>
        /// Set of allowed MAC addresses to be excluded from BPDU filtering
        /// </summary>
        public InputList<string> BpduFilterWhitelists
        {
            get => _bpduFilterWhitelists ?? (_bpduFilterWhitelists = new InputList<string>());
            set => _bpduFilterWhitelists = value;
        }

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("rateLimits")]
        public Input<Inputs.SwitchSecuritySwitchingProfileRateLimitsArgs>? RateLimits { get; set; }

        [Input("tags")]
        private InputList<Inputs.SwitchSecuritySwitchingProfileTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.SwitchSecuritySwitchingProfileTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.SwitchSecuritySwitchingProfileTagArgs>());
            set => _tags = value;
        }

        public SwitchSecuritySwitchingProfileArgs()
        {
        }
    }

    public sealed class SwitchSecuritySwitchingProfileState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Indicates whether DHCP client blocking is enabled
        /// </summary>
        [Input("blockClientDhcp")]
        public Input<bool>? BlockClientDhcp { get; set; }

        /// <summary>
        /// Block all traffic except IP/(G)ARP/BPDU
        /// </summary>
        [Input("blockNonIp")]
        public Input<bool>? BlockNonIp { get; set; }

        /// <summary>
        /// Indicates whether DHCP server blocking is enabled
        /// </summary>
        [Input("blockServerDhcp")]
        public Input<bool>? BlockServerDhcp { get; set; }

        /// <summary>
        /// Indicates whether BPDU filter is enabled
        /// </summary>
        [Input("bpduFilterEnabled")]
        public Input<bool>? BpduFilterEnabled { get; set; }

        [Input("bpduFilterWhitelists")]
        private InputList<string>? _bpduFilterWhitelists;

        /// <summary>
        /// Set of allowed MAC addresses to be excluded from BPDU filtering
        /// </summary>
        public InputList<string> BpduFilterWhitelists
        {
            get => _bpduFilterWhitelists ?? (_bpduFilterWhitelists = new InputList<string>());
            set => _bpduFilterWhitelists = value;
        }

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("rateLimits")]
        public Input<Inputs.SwitchSecuritySwitchingProfileRateLimitsGetArgs>? RateLimits { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.SwitchSecuritySwitchingProfileTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.SwitchSecuritySwitchingProfileTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.SwitchSecuritySwitchingProfileTagGetArgs>());
            set => _tags = value;
        }

        public SwitchSecuritySwitchingProfileState()
        {
        }
    }
}
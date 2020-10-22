// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class IPDiscoverySwitchingProfile : Pulumi.CustomResource
    {
        /// <summary>
        /// Limit for the amount of ARP bindings
        /// </summary>
        [Output("arpBindingsLimit")]
        public Output<int?> ArpBindingsLimit { get; private set; } = null!;

        /// <summary>
        /// Indicates whether ARP snooping is enabled
        /// </summary>
        [Output("arpSnoopingEnabled")]
        public Output<bool?> ArpSnoopingEnabled { get; private set; } = null!;

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Output("description")]
        public Output<string?> Description { get; private set; } = null!;

        /// <summary>
        /// Indicates whether DHCP snooping is enabled
        /// </summary>
        [Output("dhcpSnoopingEnabled")]
        public Output<bool?> DhcpSnoopingEnabled { get; private set; } = null!;

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.IPDiscoverySwitchingProfileTag>> Tags { get; private set; } = null!;

        /// <summary>
        /// Indicating whether VM tools will be enabled. This option is only supported on ESX where vm-tools is installed
        /// </summary>
        [Output("vmToolsEnabled")]
        public Output<bool?> VmToolsEnabled { get; private set; } = null!;


        /// <summary>
        /// Create a IPDiscoverySwitchingProfile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public IPDiscoverySwitchingProfile(string name, IPDiscoverySwitchingProfileArgs? args = null, CustomResourceOptions? options = null)
            : base("nsxt:index/iPDiscoverySwitchingProfile:IPDiscoverySwitchingProfile", name, args ?? new IPDiscoverySwitchingProfileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private IPDiscoverySwitchingProfile(string name, Input<string> id, IPDiscoverySwitchingProfileState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/iPDiscoverySwitchingProfile:IPDiscoverySwitchingProfile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing IPDiscoverySwitchingProfile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static IPDiscoverySwitchingProfile Get(string name, Input<string> id, IPDiscoverySwitchingProfileState? state = null, CustomResourceOptions? options = null)
        {
            return new IPDiscoverySwitchingProfile(name, id, state, options);
        }
    }

    public sealed class IPDiscoverySwitchingProfileArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Limit for the amount of ARP bindings
        /// </summary>
        [Input("arpBindingsLimit")]
        public Input<int>? ArpBindingsLimit { get; set; }

        /// <summary>
        /// Indicates whether ARP snooping is enabled
        /// </summary>
        [Input("arpSnoopingEnabled")]
        public Input<bool>? ArpSnoopingEnabled { get; set; }

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Indicates whether DHCP snooping is enabled
        /// </summary>
        [Input("dhcpSnoopingEnabled")]
        public Input<bool>? DhcpSnoopingEnabled { get; set; }

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("tags")]
        private InputList<Inputs.IPDiscoverySwitchingProfileTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.IPDiscoverySwitchingProfileTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.IPDiscoverySwitchingProfileTagArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// Indicating whether VM tools will be enabled. This option is only supported on ESX where vm-tools is installed
        /// </summary>
        [Input("vmToolsEnabled")]
        public Input<bool>? VmToolsEnabled { get; set; }

        public IPDiscoverySwitchingProfileArgs()
        {
        }
    }

    public sealed class IPDiscoverySwitchingProfileState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Limit for the amount of ARP bindings
        /// </summary>
        [Input("arpBindingsLimit")]
        public Input<int>? ArpBindingsLimit { get; set; }

        /// <summary>
        /// Indicates whether ARP snooping is enabled
        /// </summary>
        [Input("arpSnoopingEnabled")]
        public Input<bool>? ArpSnoopingEnabled { get; set; }

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Indicates whether DHCP snooping is enabled
        /// </summary>
        [Input("dhcpSnoopingEnabled")]
        public Input<bool>? DhcpSnoopingEnabled { get; set; }

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.IPDiscoverySwitchingProfileTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.IPDiscoverySwitchingProfileTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.IPDiscoverySwitchingProfileTagGetArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// Indicating whether VM tools will be enabled. This option is only supported on ESX where vm-tools is installed
        /// </summary>
        [Input("vmToolsEnabled")]
        public Input<bool>? VmToolsEnabled { get; set; }

        public IPDiscoverySwitchingProfileState()
        {
        }
    }
}

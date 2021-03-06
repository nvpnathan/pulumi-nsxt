// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class LogicalDHCPPort : Pulumi.CustomResource
    {
        /// <summary>
        /// Represents Desired state of the object
        /// </summary>
        [Output("adminState")]
        public Output<string?> AdminState { get; private set; } = null!;

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Output("description")]
        public Output<string?> Description { get; private set; } = null!;

        /// <summary>
        /// Id of the Logical DHCP server this port belongs to
        /// </summary>
        [Output("dhcpServerId")]
        public Output<string> DhcpServerId { get; private set; } = null!;

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Output("displayName")]
        public Output<string> DisplayName { get; private set; } = null!;

        /// <summary>
        /// Id of the Logical switch that this port belongs to
        /// </summary>
        [Output("logicalSwitchId")]
        public Output<string> LogicalSwitchId { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.LogicalDHCPPortTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a LogicalDHCPPort resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LogicalDHCPPort(string name, LogicalDHCPPortArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/logicalDHCPPort:LogicalDHCPPort", name, args ?? new LogicalDHCPPortArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LogicalDHCPPort(string name, Input<string> id, LogicalDHCPPortState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/logicalDHCPPort:LogicalDHCPPort", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LogicalDHCPPort resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LogicalDHCPPort Get(string name, Input<string> id, LogicalDHCPPortState? state = null, CustomResourceOptions? options = null)
        {
            return new LogicalDHCPPort(name, id, state, options);
        }
    }

    public sealed class LogicalDHCPPortArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Represents Desired state of the object
        /// </summary>
        [Input("adminState")]
        public Input<string>? AdminState { get; set; }

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Id of the Logical DHCP server this port belongs to
        /// </summary>
        [Input("dhcpServerId", required: true)]
        public Input<string> DhcpServerId { get; set; } = null!;

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Id of the Logical switch that this port belongs to
        /// </summary>
        [Input("logicalSwitchId", required: true)]
        public Input<string> LogicalSwitchId { get; set; } = null!;

        [Input("tags")]
        private InputList<Inputs.LogicalDHCPPortTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LogicalDHCPPortTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LogicalDHCPPortTagArgs>());
            set => _tags = value;
        }

        public LogicalDHCPPortArgs()
        {
        }
    }

    public sealed class LogicalDHCPPortState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Represents Desired state of the object
        /// </summary>
        [Input("adminState")]
        public Input<string>? AdminState { get; set; }

        /// <summary>
        /// Description of this resource
        /// </summary>
        [Input("description")]
        public Input<string>? Description { get; set; }

        /// <summary>
        /// Id of the Logical DHCP server this port belongs to
        /// </summary>
        [Input("dhcpServerId")]
        public Input<string>? DhcpServerId { get; set; }

        /// <summary>
        /// The display name of this resource. Defaults to ID if not set
        /// </summary>
        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        /// <summary>
        /// Id of the Logical switch that this port belongs to
        /// </summary>
        [Input("logicalSwitchId")]
        public Input<string>? LogicalSwitchId { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.LogicalDHCPPortTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LogicalDHCPPortTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LogicalDHCPPortTagGetArgs>());
            set => _tags = value;
        }

        public LogicalDHCPPortState()
        {
        }
    }
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class LBPassiveMonitor : Pulumi.CustomResource
    {
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

        /// <summary>
        /// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
        /// period
        /// </summary>
        [Output("maxFails")]
        public Output<int?> MaxFails { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.LBPassiveMonitorTag>> Tags { get; private set; } = null!;

        /// <summary>
        /// After this timeout period, the member is tried again for a new connection to see if it is available
        /// </summary>
        [Output("timeout")]
        public Output<int?> Timeout { get; private set; } = null!;


        /// <summary>
        /// Create a LBPassiveMonitor resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LBPassiveMonitor(string name, LBPassiveMonitorArgs? args = null, CustomResourceOptions? options = null)
            : base("nsxt:index/lBPassiveMonitor:LBPassiveMonitor", name, args ?? new LBPassiveMonitorArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LBPassiveMonitor(string name, Input<string> id, LBPassiveMonitorState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/lBPassiveMonitor:LBPassiveMonitor", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LBPassiveMonitor resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LBPassiveMonitor Get(string name, Input<string> id, LBPassiveMonitorState? state = null, CustomResourceOptions? options = null)
        {
            return new LBPassiveMonitor(name, id, state, options);
        }
    }

    public sealed class LBPassiveMonitorArgs : Pulumi.ResourceArgs
    {
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

        /// <summary>
        /// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
        /// period
        /// </summary>
        [Input("maxFails")]
        public Input<int>? MaxFails { get; set; }

        [Input("tags")]
        private InputList<Inputs.LBPassiveMonitorTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBPassiveMonitorTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBPassiveMonitorTagArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// After this timeout period, the member is tried again for a new connection to see if it is available
        /// </summary>
        [Input("timeout")]
        public Input<int>? Timeout { get; set; }

        public LBPassiveMonitorArgs()
        {
        }
    }

    public sealed class LBPassiveMonitorState : Pulumi.ResourceArgs
    {
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

        /// <summary>
        /// When the consecutive failures reach this value, then the member is considered temporarily unavailable for a configurable
        /// period
        /// </summary>
        [Input("maxFails")]
        public Input<int>? MaxFails { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.LBPassiveMonitorTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBPassiveMonitorTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBPassiveMonitorTagGetArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// After this timeout period, the member is tried again for a new connection to see if it is available
        /// </summary>
        [Input("timeout")]
        public Input<int>? Timeout { get; set; }

        public LBPassiveMonitorState()
        {
        }
    }
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class LBFastUDPApplicationProfile : Pulumi.CustomResource
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
        /// A boolean flag which reflects whether flow mirroring is enabled, and all the flows to the bounded virtual server are
        /// mirrored to the standby node
        /// </summary>
        [Output("haFlowMirroring")]
        public Output<bool?> HaFlowMirroring { get; private set; } = null!;

        /// <summary>
        /// Timeout in seconds to specify how long an idle UDP connection in ESTABLISHED state should be kept for this application
        /// before cleaning up
        /// </summary>
        [Output("idleTimeout")]
        public Output<int?> IdleTimeout { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.LBFastUDPApplicationProfileTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a LBFastUDPApplicationProfile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LBFastUDPApplicationProfile(string name, LBFastUDPApplicationProfileArgs? args = null, CustomResourceOptions? options = null)
            : base("nsxt:index/lBFastUDPApplicationProfile:LBFastUDPApplicationProfile", name, args ?? new LBFastUDPApplicationProfileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LBFastUDPApplicationProfile(string name, Input<string> id, LBFastUDPApplicationProfileState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/lBFastUDPApplicationProfile:LBFastUDPApplicationProfile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LBFastUDPApplicationProfile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LBFastUDPApplicationProfile Get(string name, Input<string> id, LBFastUDPApplicationProfileState? state = null, CustomResourceOptions? options = null)
        {
            return new LBFastUDPApplicationProfile(name, id, state, options);
        }
    }

    public sealed class LBFastUDPApplicationProfileArgs : Pulumi.ResourceArgs
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
        /// A boolean flag which reflects whether flow mirroring is enabled, and all the flows to the bounded virtual server are
        /// mirrored to the standby node
        /// </summary>
        [Input("haFlowMirroring")]
        public Input<bool>? HaFlowMirroring { get; set; }

        /// <summary>
        /// Timeout in seconds to specify how long an idle UDP connection in ESTABLISHED state should be kept for this application
        /// before cleaning up
        /// </summary>
        [Input("idleTimeout")]
        public Input<int>? IdleTimeout { get; set; }

        [Input("tags")]
        private InputList<Inputs.LBFastUDPApplicationProfileTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBFastUDPApplicationProfileTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBFastUDPApplicationProfileTagArgs>());
            set => _tags = value;
        }

        public LBFastUDPApplicationProfileArgs()
        {
        }
    }

    public sealed class LBFastUDPApplicationProfileState : Pulumi.ResourceArgs
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
        /// A boolean flag which reflects whether flow mirroring is enabled, and all the flows to the bounded virtual server are
        /// mirrored to the standby node
        /// </summary>
        [Input("haFlowMirroring")]
        public Input<bool>? HaFlowMirroring { get; set; }

        /// <summary>
        /// Timeout in seconds to specify how long an idle UDP connection in ESTABLISHED state should be kept for this application
        /// before cleaning up
        /// </summary>
        [Input("idleTimeout")]
        public Input<int>? IdleTimeout { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.LBFastUDPApplicationProfileTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBFastUDPApplicationProfileTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBFastUDPApplicationProfileTagGetArgs>());
            set => _tags = value;
        }

        public LBFastUDPApplicationProfileState()
        {
        }
    }
}

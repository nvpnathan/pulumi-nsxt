// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class EtherTypeNSService : Pulumi.CustomResource
    {
        /// <summary>
        /// A boolean flag which reflects whether this is a default NSServices which can't be modified/deleted
        /// </summary>
        [Output("defaultService")]
        public Output<bool> DefaultService { get; private set; } = null!;

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
        /// Type of the encapsulated protocol
        /// </summary>
        [Output("etherType")]
        public Output<int> EtherType { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.EtherTypeNSServiceTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a EtherTypeNSService resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public EtherTypeNSService(string name, EtherTypeNSServiceArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/etherTypeNSService:EtherTypeNSService", name, args ?? new EtherTypeNSServiceArgs(), MakeResourceOptions(options, ""))
        {
        }

        private EtherTypeNSService(string name, Input<string> id, EtherTypeNSServiceState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/etherTypeNSService:EtherTypeNSService", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing EtherTypeNSService resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static EtherTypeNSService Get(string name, Input<string> id, EtherTypeNSServiceState? state = null, CustomResourceOptions? options = null)
        {
            return new EtherTypeNSService(name, id, state, options);
        }
    }

    public sealed class EtherTypeNSServiceArgs : Pulumi.ResourceArgs
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
        /// Type of the encapsulated protocol
        /// </summary>
        [Input("etherType", required: true)]
        public Input<int> EtherType { get; set; } = null!;

        [Input("tags")]
        private InputList<Inputs.EtherTypeNSServiceTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.EtherTypeNSServiceTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.EtherTypeNSServiceTagArgs>());
            set => _tags = value;
        }

        public EtherTypeNSServiceArgs()
        {
        }
    }

    public sealed class EtherTypeNSServiceState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// A boolean flag which reflects whether this is a default NSServices which can't be modified/deleted
        /// </summary>
        [Input("defaultService")]
        public Input<bool>? DefaultService { get; set; }

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
        /// Type of the encapsulated protocol
        /// </summary>
        [Input("etherType")]
        public Input<int>? EtherType { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.EtherTypeNSServiceTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.EtherTypeNSServiceTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.EtherTypeNSServiceTagGetArgs>());
            set => _tags = value;
        }

        public EtherTypeNSServiceState()
        {
        }
    }
}
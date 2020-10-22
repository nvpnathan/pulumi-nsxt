// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class NSServiceGroup : Pulumi.CustomResource
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
        /// List of NSService or NSServiceGroup resources that can be added as members to an NSServiceGroup
        /// </summary>
        [Output("members")]
        public Output<ImmutableArray<string>> Members { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.NSServiceGroupTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a NSServiceGroup resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public NSServiceGroup(string name, NSServiceGroupArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/nSServiceGroup:NSServiceGroup", name, args ?? new NSServiceGroupArgs(), MakeResourceOptions(options, ""))
        {
        }

        private NSServiceGroup(string name, Input<string> id, NSServiceGroupState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/nSServiceGroup:NSServiceGroup", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing NSServiceGroup resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static NSServiceGroup Get(string name, Input<string> id, NSServiceGroupState? state = null, CustomResourceOptions? options = null)
        {
            return new NSServiceGroup(name, id, state, options);
        }
    }

    public sealed class NSServiceGroupArgs : Pulumi.ResourceArgs
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

        [Input("members", required: true)]
        private InputList<string>? _members;

        /// <summary>
        /// List of NSService or NSServiceGroup resources that can be added as members to an NSServiceGroup
        /// </summary>
        public InputList<string> Members
        {
            get => _members ?? (_members = new InputList<string>());
            set => _members = value;
        }

        [Input("tags")]
        private InputList<Inputs.NSServiceGroupTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.NSServiceGroupTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.NSServiceGroupTagArgs>());
            set => _tags = value;
        }

        public NSServiceGroupArgs()
        {
        }
    }

    public sealed class NSServiceGroupState : Pulumi.ResourceArgs
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

        [Input("members")]
        private InputList<string>? _members;

        /// <summary>
        /// List of NSService or NSServiceGroup resources that can be added as members to an NSServiceGroup
        /// </summary>
        public InputList<string> Members
        {
            get => _members ?? (_members = new InputList<string>());
            set => _members = value;
        }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.NSServiceGroupTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.NSServiceGroupTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.NSServiceGroupTagGetArgs>());
            set => _tags = value;
        }

        public NSServiceGroupState()
        {
        }
    }
}
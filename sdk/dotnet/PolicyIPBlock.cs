// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicyIPBlock : Pulumi.CustomResource
    {
        /// <summary>
        /// Network address and the prefix length which will be associated with a layer-2 broadcast domain
        /// </summary>
        [Output("cidr")]
        public Output<string> Cidr { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.PolicyIPBlockTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a PolicyIPBlock resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicyIPBlock(string name, PolicyIPBlockArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policyIPBlock:PolicyIPBlock", name, args ?? new PolicyIPBlockArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicyIPBlock(string name, Input<string> id, PolicyIPBlockState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policyIPBlock:PolicyIPBlock", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PolicyIPBlock resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicyIPBlock Get(string name, Input<string> id, PolicyIPBlockState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicyIPBlock(name, id, state, options);
        }
    }

    public sealed class PolicyIPBlockArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Network address and the prefix length which will be associated with a layer-2 broadcast domain
        /// </summary>
        [Input("cidr", required: true)]
        public Input<string> Cidr { get; set; } = null!;

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
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicyIPBlockTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyIPBlockTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyIPBlockTagArgs>());
            set => _tags = value;
        }

        public PolicyIPBlockArgs()
        {
        }
    }

    public sealed class PolicyIPBlockState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Network address and the prefix length which will be associated with a layer-2 broadcast domain
        /// </summary>
        [Input("cidr")]
        public Input<string>? Cidr { get; set; }

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
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicyIPBlockTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyIPBlockTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyIPBlockTagGetArgs>());
            set => _tags = value;
        }

        public PolicyIPBlockState()
        {
        }
    }
}
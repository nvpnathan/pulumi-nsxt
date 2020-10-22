// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class VMTags : Pulumi.CustomResource
    {
        /// <summary>
        /// Instance id
        /// </summary>
        [Output("instanceId")]
        public Output<string> InstanceId { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("logicalPortTags")]
        public Output<ImmutableArray<Outputs.VMTagsLogicalPortTag>> LogicalPortTags { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.VMTagsTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a VMTags resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public VMTags(string name, VMTagsArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/vMTags:VMTags", name, args ?? new VMTagsArgs(), MakeResourceOptions(options, ""))
        {
        }

        private VMTags(string name, Input<string> id, VMTagsState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/vMTags:VMTags", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing VMTags resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static VMTags Get(string name, Input<string> id, VMTagsState? state = null, CustomResourceOptions? options = null)
        {
            return new VMTags(name, id, state, options);
        }
    }

    public sealed class VMTagsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Instance id
        /// </summary>
        [Input("instanceId", required: true)]
        public Input<string> InstanceId { get; set; } = null!;

        [Input("logicalPortTags")]
        private InputList<Inputs.VMTagsLogicalPortTagArgs>? _logicalPortTags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.VMTagsLogicalPortTagArgs> LogicalPortTags
        {
            get => _logicalPortTags ?? (_logicalPortTags = new InputList<Inputs.VMTagsLogicalPortTagArgs>());
            set => _logicalPortTags = value;
        }

        [Input("tags")]
        private InputList<Inputs.VMTagsTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.VMTagsTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.VMTagsTagArgs>());
            set => _tags = value;
        }

        public VMTagsArgs()
        {
        }
    }

    public sealed class VMTagsState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Instance id
        /// </summary>
        [Input("instanceId")]
        public Input<string>? InstanceId { get; set; }

        [Input("logicalPortTags")]
        private InputList<Inputs.VMTagsLogicalPortTagGetArgs>? _logicalPortTags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.VMTagsLogicalPortTagGetArgs> LogicalPortTags
        {
            get => _logicalPortTags ?? (_logicalPortTags = new InputList<Inputs.VMTagsLogicalPortTagGetArgs>());
            set => _logicalPortTags = value;
        }

        [Input("tags")]
        private InputList<Inputs.VMTagsTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.VMTagsTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.VMTagsTagGetArgs>());
            set => _tags = value;
        }

        public VMTagsState()
        {
        }
    }
}
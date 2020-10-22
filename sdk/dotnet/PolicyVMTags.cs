// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicyVMTags : Pulumi.CustomResource
    {
        /// <summary>
        /// Instance id
        /// </summary>
        [Output("instanceId")]
        public Output<string> InstanceId { get; private set; } = null!;

        /// <summary>
        /// Tag specificiation for corresponding segment port
        /// </summary>
        [Output("ports")]
        public Output<ImmutableArray<Outputs.PolicyVMTagsPort>> Ports { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.PolicyVMTagsTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a PolicyVMTags resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicyVMTags(string name, PolicyVMTagsArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policyVMTags:PolicyVMTags", name, args ?? new PolicyVMTagsArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicyVMTags(string name, Input<string> id, PolicyVMTagsState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policyVMTags:PolicyVMTags", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PolicyVMTags resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicyVMTags Get(string name, Input<string> id, PolicyVMTagsState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicyVMTags(name, id, state, options);
        }
    }

    public sealed class PolicyVMTagsArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Instance id
        /// </summary>
        [Input("instanceId", required: true)]
        public Input<string> InstanceId { get; set; } = null!;

        [Input("ports")]
        private InputList<Inputs.PolicyVMTagsPortArgs>? _ports;

        /// <summary>
        /// Tag specificiation for corresponding segment port
        /// </summary>
        public InputList<Inputs.PolicyVMTagsPortArgs> Ports
        {
            get => _ports ?? (_ports = new InputList<Inputs.PolicyVMTagsPortArgs>());
            set => _ports = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyVMTagsTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyVMTagsTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyVMTagsTagArgs>());
            set => _tags = value;
        }

        public PolicyVMTagsArgs()
        {
        }
    }

    public sealed class PolicyVMTagsState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Instance id
        /// </summary>
        [Input("instanceId")]
        public Input<string>? InstanceId { get; set; }

        [Input("ports")]
        private InputList<Inputs.PolicyVMTagsPortGetArgs>? _ports;

        /// <summary>
        /// Tag specificiation for corresponding segment port
        /// </summary>
        public InputList<Inputs.PolicyVMTagsPortGetArgs> Ports
        {
            get => _ports ?? (_ports = new InputList<Inputs.PolicyVMTagsPortGetArgs>());
            set => _ports = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyVMTagsTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyVMTagsTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyVMTagsTagGetArgs>());
            set => _tags = value;
        }

        public PolicyVMTagsState()
        {
        }
    }
}

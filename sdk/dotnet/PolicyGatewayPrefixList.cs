// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicyGatewayPrefixList : Pulumi.CustomResource
    {
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
        /// Policy path for Tier0 gateway
        /// </summary>
        [Output("gatewayPath")]
        public Output<string> GatewayPath { get; private set; } = null!;

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
        /// Ordered list of network prefixes
        /// </summary>
        [Output("prefixes")]
        public Output<ImmutableArray<Outputs.PolicyGatewayPrefixListPrefix>> Prefixes { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.PolicyGatewayPrefixListTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a PolicyGatewayPrefixList resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicyGatewayPrefixList(string name, PolicyGatewayPrefixListArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policyGatewayPrefixList:PolicyGatewayPrefixList", name, args ?? new PolicyGatewayPrefixListArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicyGatewayPrefixList(string name, Input<string> id, PolicyGatewayPrefixListState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policyGatewayPrefixList:PolicyGatewayPrefixList", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PolicyGatewayPrefixList resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicyGatewayPrefixList Get(string name, Input<string> id, PolicyGatewayPrefixListState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicyGatewayPrefixList(name, id, state, options);
        }
    }

    public sealed class PolicyGatewayPrefixListArgs : Pulumi.ResourceArgs
    {
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
        /// Policy path for Tier0 gateway
        /// </summary>
        [Input("gatewayPath", required: true)]
        public Input<string> GatewayPath { get; set; } = null!;

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        [Input("prefixes", required: true)]
        private InputList<Inputs.PolicyGatewayPrefixListPrefixArgs>? _prefixes;

        /// <summary>
        /// Ordered list of network prefixes
        /// </summary>
        public InputList<Inputs.PolicyGatewayPrefixListPrefixArgs> Prefixes
        {
            get => _prefixes ?? (_prefixes = new InputList<Inputs.PolicyGatewayPrefixListPrefixArgs>());
            set => _prefixes = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyGatewayPrefixListTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyGatewayPrefixListTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyGatewayPrefixListTagArgs>());
            set => _tags = value;
        }

        public PolicyGatewayPrefixListArgs()
        {
        }
    }

    public sealed class PolicyGatewayPrefixListState : Pulumi.ResourceArgs
    {
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
        /// Policy path for Tier0 gateway
        /// </summary>
        [Input("gatewayPath")]
        public Input<string>? GatewayPath { get; set; }

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

        [Input("prefixes")]
        private InputList<Inputs.PolicyGatewayPrefixListPrefixGetArgs>? _prefixes;

        /// <summary>
        /// Ordered list of network prefixes
        /// </summary>
        public InputList<Inputs.PolicyGatewayPrefixListPrefixGetArgs> Prefixes
        {
            get => _prefixes ?? (_prefixes = new InputList<Inputs.PolicyGatewayPrefixListPrefixGetArgs>());
            set => _prefixes = value;
        }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicyGatewayPrefixListTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyGatewayPrefixListTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyGatewayPrefixListTagGetArgs>());
            set => _tags = value;
        }

        public PolicyGatewayPrefixListState()
        {
        }
    }
}
// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicyDHCPRelay : Pulumi.CustomResource
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

        [Output("serverAddresses")]
        public Output<ImmutableArray<string>> ServerAddresses { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.PolicyDHCPRelayTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a PolicyDHCPRelay resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicyDHCPRelay(string name, PolicyDHCPRelayArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policyDHCPRelay:PolicyDHCPRelay", name, args ?? new PolicyDHCPRelayArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicyDHCPRelay(string name, Input<string> id, PolicyDHCPRelayState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policyDHCPRelay:PolicyDHCPRelay", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PolicyDHCPRelay resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicyDHCPRelay Get(string name, Input<string> id, PolicyDHCPRelayState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicyDHCPRelay(name, id, state, options);
        }
    }

    public sealed class PolicyDHCPRelayArgs : Pulumi.ResourceArgs
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
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        [Input("serverAddresses", required: true)]
        private InputList<string>? _serverAddresses;
        public InputList<string> ServerAddresses
        {
            get => _serverAddresses ?? (_serverAddresses = new InputList<string>());
            set => _serverAddresses = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyDHCPRelayTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyDHCPRelayTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyDHCPRelayTagArgs>());
            set => _tags = value;
        }

        public PolicyDHCPRelayArgs()
        {
        }
    }

    public sealed class PolicyDHCPRelayState : Pulumi.ResourceArgs
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

        [Input("serverAddresses")]
        private InputList<string>? _serverAddresses;
        public InputList<string> ServerAddresses
        {
            get => _serverAddresses ?? (_serverAddresses = new InputList<string>());
            set => _serverAddresses = value;
        }

        [Input("tags")]
        private InputList<Inputs.PolicyDHCPRelayTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyDHCPRelayTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyDHCPRelayTagGetArgs>());
            set => _tags = value;
        }

        public PolicyDHCPRelayState()
        {
        }
    }
}

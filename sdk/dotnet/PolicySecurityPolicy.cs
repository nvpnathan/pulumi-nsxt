// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicySecurityPolicy : Pulumi.CustomResource
    {
        /// <summary>
        /// Category
        /// </summary>
        [Output("category")]
        public Output<string> Category { get; private set; } = null!;

        /// <summary>
        /// Comments for security policy lock/unlock
        /// </summary>
        [Output("comments")]
        public Output<string?> Comments { get; private set; } = null!;

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
        /// The domain name to use for resources. If not specified 'default' is used
        /// </summary>
        [Output("domain")]
        public Output<string?> Domain { get; private set; } = null!;

        /// <summary>
        /// Indicates whether a security policy should be locked. If locked by a user, no other user would be able to modify this
        /// policy
        /// </summary>
        [Output("locked")]
        public Output<bool?> Locked { get; private set; } = null!;

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
        /// List of rules in the section
        /// </summary>
        [Output("rules")]
        public Output<ImmutableArray<Outputs.PolicySecurityPolicyRule>> Rules { get; private set; } = null!;

        /// <summary>
        /// The list of group paths where the rules in this policy will get applied
        /// </summary>
        [Output("scopes")]
        public Output<ImmutableArray<string>> Scopes { get; private set; } = null!;

        /// <summary>
        /// This field is used to resolve conflicts between security policies across domains
        /// </summary>
        [Output("sequenceNumber")]
        public Output<int?> SequenceNumber { get; private set; } = null!;

        /// <summary>
        /// When it is stateful, the state of the network connects are tracked and a stateful packet inspection is performed
        /// </summary>
        [Output("stateful")]
        public Output<bool?> Stateful { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.PolicySecurityPolicyTag>> Tags { get; private set; } = null!;

        /// <summary>
        /// Ensures that a 3 way TCP handshake is done before the data packets are sent
        /// </summary>
        [Output("tcpStrict")]
        public Output<bool> TcpStrict { get; private set; } = null!;


        /// <summary>
        /// Create a PolicySecurityPolicy resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicySecurityPolicy(string name, PolicySecurityPolicyArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policySecurityPolicy:PolicySecurityPolicy", name, args ?? new PolicySecurityPolicyArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicySecurityPolicy(string name, Input<string> id, PolicySecurityPolicyState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policySecurityPolicy:PolicySecurityPolicy", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PolicySecurityPolicy resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicySecurityPolicy Get(string name, Input<string> id, PolicySecurityPolicyState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicySecurityPolicy(name, id, state, options);
        }
    }

    public sealed class PolicySecurityPolicyArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Category
        /// </summary>
        [Input("category", required: true)]
        public Input<string> Category { get; set; } = null!;

        /// <summary>
        /// Comments for security policy lock/unlock
        /// </summary>
        [Input("comments")]
        public Input<string>? Comments { get; set; }

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
        /// The domain name to use for resources. If not specified 'default' is used
        /// </summary>
        [Input("domain")]
        public Input<string>? Domain { get; set; }

        /// <summary>
        /// Indicates whether a security policy should be locked. If locked by a user, no other user would be able to modify this
        /// policy
        /// </summary>
        [Input("locked")]
        public Input<bool>? Locked { get; set; }

        /// <summary>
        /// NSX ID for this resource
        /// </summary>
        [Input("nsxId")]
        public Input<string>? NsxId { get; set; }

        [Input("rules")]
        private InputList<Inputs.PolicySecurityPolicyRuleArgs>? _rules;

        /// <summary>
        /// List of rules in the section
        /// </summary>
        public InputList<Inputs.PolicySecurityPolicyRuleArgs> Rules
        {
            get => _rules ?? (_rules = new InputList<Inputs.PolicySecurityPolicyRuleArgs>());
            set => _rules = value;
        }

        [Input("scopes")]
        private InputList<string>? _scopes;

        /// <summary>
        /// The list of group paths where the rules in this policy will get applied
        /// </summary>
        public InputList<string> Scopes
        {
            get => _scopes ?? (_scopes = new InputList<string>());
            set => _scopes = value;
        }

        /// <summary>
        /// This field is used to resolve conflicts between security policies across domains
        /// </summary>
        [Input("sequenceNumber")]
        public Input<int>? SequenceNumber { get; set; }

        /// <summary>
        /// When it is stateful, the state of the network connects are tracked and a stateful packet inspection is performed
        /// </summary>
        [Input("stateful")]
        public Input<bool>? Stateful { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicySecurityPolicyTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicySecurityPolicyTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicySecurityPolicyTagArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// Ensures that a 3 way TCP handshake is done before the data packets are sent
        /// </summary>
        [Input("tcpStrict")]
        public Input<bool>? TcpStrict { get; set; }

        public PolicySecurityPolicyArgs()
        {
        }
    }

    public sealed class PolicySecurityPolicyState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Category
        /// </summary>
        [Input("category")]
        public Input<string>? Category { get; set; }

        /// <summary>
        /// Comments for security policy lock/unlock
        /// </summary>
        [Input("comments")]
        public Input<string>? Comments { get; set; }

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
        /// The domain name to use for resources. If not specified 'default' is used
        /// </summary>
        [Input("domain")]
        public Input<string>? Domain { get; set; }

        /// <summary>
        /// Indicates whether a security policy should be locked. If locked by a user, no other user would be able to modify this
        /// policy
        /// </summary>
        [Input("locked")]
        public Input<bool>? Locked { get; set; }

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

        [Input("rules")]
        private InputList<Inputs.PolicySecurityPolicyRuleGetArgs>? _rules;

        /// <summary>
        /// List of rules in the section
        /// </summary>
        public InputList<Inputs.PolicySecurityPolicyRuleGetArgs> Rules
        {
            get => _rules ?? (_rules = new InputList<Inputs.PolicySecurityPolicyRuleGetArgs>());
            set => _rules = value;
        }

        [Input("scopes")]
        private InputList<string>? _scopes;

        /// <summary>
        /// The list of group paths where the rules in this policy will get applied
        /// </summary>
        public InputList<string> Scopes
        {
            get => _scopes ?? (_scopes = new InputList<string>());
            set => _scopes = value;
        }

        /// <summary>
        /// This field is used to resolve conflicts between security policies across domains
        /// </summary>
        [Input("sequenceNumber")]
        public Input<int>? SequenceNumber { get; set; }

        /// <summary>
        /// When it is stateful, the state of the network connects are tracked and a stateful packet inspection is performed
        /// </summary>
        [Input("stateful")]
        public Input<bool>? Stateful { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicySecurityPolicyTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicySecurityPolicyTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicySecurityPolicyTagGetArgs>());
            set => _tags = value;
        }

        /// <summary>
        /// Ensures that a 3 way TCP handshake is done before the data packets are sent
        /// </summary>
        [Input("tcpStrict")]
        public Input<bool>? TcpStrict { get; set; }

        public PolicySecurityPolicyState()
        {
        }
    }
}

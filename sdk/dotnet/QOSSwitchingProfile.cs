// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class QOSSwitchingProfile : Pulumi.CustomResource
    {
        /// <summary>
        /// Class of service
        /// </summary>
        [Output("classOfService")]
        public Output<int?> ClassOfService { get; private set; } = null!;

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
        /// DSCP Priority
        /// </summary>
        [Output("dscpPriority")]
        public Output<int?> DscpPriority { get; private set; } = null!;

        /// <summary>
        /// Trust mode for DSCP
        /// </summary>
        [Output("dscpTrusted")]
        public Output<bool?> DscpTrusted { get; private set; } = null!;

        [Output("egressRateShaper")]
        public Output<Outputs.QOSSwitchingProfileEgressRateShaper?> EgressRateShaper { get; private set; } = null!;

        [Output("ingressBroadcastRateShaper")]
        public Output<Outputs.QOSSwitchingProfileIngressBroadcastRateShaper?> IngressBroadcastRateShaper { get; private set; } = null!;

        [Output("ingressRateShaper")]
        public Output<Outputs.QOSSwitchingProfileIngressRateShaper?> IngressRateShaper { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.QOSSwitchingProfileTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a QOSSwitchingProfile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public QOSSwitchingProfile(string name, QOSSwitchingProfileArgs? args = null, CustomResourceOptions? options = null)
            : base("nsxt:index/qOSSwitchingProfile:QOSSwitchingProfile", name, args ?? new QOSSwitchingProfileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private QOSSwitchingProfile(string name, Input<string> id, QOSSwitchingProfileState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/qOSSwitchingProfile:QOSSwitchingProfile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing QOSSwitchingProfile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static QOSSwitchingProfile Get(string name, Input<string> id, QOSSwitchingProfileState? state = null, CustomResourceOptions? options = null)
        {
            return new QOSSwitchingProfile(name, id, state, options);
        }
    }

    public sealed class QOSSwitchingProfileArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Class of service
        /// </summary>
        [Input("classOfService")]
        public Input<int>? ClassOfService { get; set; }

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
        /// DSCP Priority
        /// </summary>
        [Input("dscpPriority")]
        public Input<int>? DscpPriority { get; set; }

        /// <summary>
        /// Trust mode for DSCP
        /// </summary>
        [Input("dscpTrusted")]
        public Input<bool>? DscpTrusted { get; set; }

        [Input("egressRateShaper")]
        public Input<Inputs.QOSSwitchingProfileEgressRateShaperArgs>? EgressRateShaper { get; set; }

        [Input("ingressBroadcastRateShaper")]
        public Input<Inputs.QOSSwitchingProfileIngressBroadcastRateShaperArgs>? IngressBroadcastRateShaper { get; set; }

        [Input("ingressRateShaper")]
        public Input<Inputs.QOSSwitchingProfileIngressRateShaperArgs>? IngressRateShaper { get; set; }

        [Input("tags")]
        private InputList<Inputs.QOSSwitchingProfileTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.QOSSwitchingProfileTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.QOSSwitchingProfileTagArgs>());
            set => _tags = value;
        }

        public QOSSwitchingProfileArgs()
        {
        }
    }

    public sealed class QOSSwitchingProfileState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Class of service
        /// </summary>
        [Input("classOfService")]
        public Input<int>? ClassOfService { get; set; }

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
        /// DSCP Priority
        /// </summary>
        [Input("dscpPriority")]
        public Input<int>? DscpPriority { get; set; }

        /// <summary>
        /// Trust mode for DSCP
        /// </summary>
        [Input("dscpTrusted")]
        public Input<bool>? DscpTrusted { get; set; }

        [Input("egressRateShaper")]
        public Input<Inputs.QOSSwitchingProfileEgressRateShaperGetArgs>? EgressRateShaper { get; set; }

        [Input("ingressBroadcastRateShaper")]
        public Input<Inputs.QOSSwitchingProfileIngressBroadcastRateShaperGetArgs>? IngressBroadcastRateShaper { get; set; }

        [Input("ingressRateShaper")]
        public Input<Inputs.QOSSwitchingProfileIngressRateShaperGetArgs>? IngressRateShaper { get; set; }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.QOSSwitchingProfileTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.QOSSwitchingProfileTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.QOSSwitchingProfileTagGetArgs>());
            set => _tags = value;
        }

        public QOSSwitchingProfileState()
        {
        }
    }
}

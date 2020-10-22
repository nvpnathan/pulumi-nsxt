// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class PolicyBGPConfig : Pulumi.CustomResource
    {
        /// <summary>
        /// Flag to enable ECMP
        /// </summary>
        [Output("ecmp")]
        public Output<bool?> Ecmp { get; private set; } = null!;

        /// <summary>
        /// Flag to enable BGP configuration
        /// </summary>
        [Output("enabled")]
        public Output<bool?> Enabled { get; private set; } = null!;

        /// <summary>
        /// Gateway for this BGP config
        /// </summary>
        [Output("gatewayPath")]
        public Output<string> GatewayPath { get; private set; } = null!;

        /// <summary>
        /// BGP Graceful Restart Configuration Mode
        /// </summary>
        [Output("gracefulRestartMode")]
        public Output<string?> GracefulRestartMode { get; private set; } = null!;

        /// <summary>
        /// BGP Stale Route Timer
        /// </summary>
        [Output("gracefulRestartStaleRouteTimer")]
        public Output<int?> GracefulRestartStaleRouteTimer { get; private set; } = null!;

        /// <summary>
        /// BGP Graceful Restart Timer
        /// </summary>
        [Output("gracefulRestartTimer")]
        public Output<int?> GracefulRestartTimer { get; private set; } = null!;

        /// <summary>
        /// Enable inter SR IBGP configuration
        /// </summary>
        [Output("interSrIbgp")]
        public Output<bool?> InterSrIbgp { get; private set; } = null!;

        /// <summary>
        /// BGP AS number in ASPLAIN/ASDOT Format
        /// </summary>
        [Output("localAsNum")]
        public Output<string?> LocalAsNum { get; private set; } = null!;

        /// <summary>
        /// Flag to enable BGP multipath relax option
        /// </summary>
        [Output("multipathRelax")]
        public Output<bool?> MultipathRelax { get; private set; } = null!;

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
        /// List of routes to be aggregated
        /// </summary>
        [Output("routeAggregations")]
        public Output<ImmutableArray<Outputs.PolicyBGPConfigRouteAggregation>> RouteAggregations { get; private set; } = null!;

        /// <summary>
        /// Site Path for this BGP config
        /// </summary>
        [Output("sitePath")]
        public Output<string> SitePath { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.PolicyBGPConfigTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a PolicyBGPConfig resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public PolicyBGPConfig(string name, PolicyBGPConfigArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/policyBGPConfig:PolicyBGPConfig", name, args ?? new PolicyBGPConfigArgs(), MakeResourceOptions(options, ""))
        {
        }

        private PolicyBGPConfig(string name, Input<string> id, PolicyBGPConfigState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/policyBGPConfig:PolicyBGPConfig", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing PolicyBGPConfig resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static PolicyBGPConfig Get(string name, Input<string> id, PolicyBGPConfigState? state = null, CustomResourceOptions? options = null)
        {
            return new PolicyBGPConfig(name, id, state, options);
        }
    }

    public sealed class PolicyBGPConfigArgs : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Flag to enable ECMP
        /// </summary>
        [Input("ecmp")]
        public Input<bool>? Ecmp { get; set; }

        /// <summary>
        /// Flag to enable BGP configuration
        /// </summary>
        [Input("enabled")]
        public Input<bool>? Enabled { get; set; }

        /// <summary>
        /// Gateway for this BGP config
        /// </summary>
        [Input("gatewayPath", required: true)]
        public Input<string> GatewayPath { get; set; } = null!;

        /// <summary>
        /// BGP Graceful Restart Configuration Mode
        /// </summary>
        [Input("gracefulRestartMode")]
        public Input<string>? GracefulRestartMode { get; set; }

        /// <summary>
        /// BGP Stale Route Timer
        /// </summary>
        [Input("gracefulRestartStaleRouteTimer")]
        public Input<int>? GracefulRestartStaleRouteTimer { get; set; }

        /// <summary>
        /// BGP Graceful Restart Timer
        /// </summary>
        [Input("gracefulRestartTimer")]
        public Input<int>? GracefulRestartTimer { get; set; }

        /// <summary>
        /// Enable inter SR IBGP configuration
        /// </summary>
        [Input("interSrIbgp")]
        public Input<bool>? InterSrIbgp { get; set; }

        /// <summary>
        /// BGP AS number in ASPLAIN/ASDOT Format
        /// </summary>
        [Input("localAsNum")]
        public Input<string>? LocalAsNum { get; set; }

        /// <summary>
        /// Flag to enable BGP multipath relax option
        /// </summary>
        [Input("multipathRelax")]
        public Input<bool>? MultipathRelax { get; set; }

        [Input("routeAggregations")]
        private InputList<Inputs.PolicyBGPConfigRouteAggregationArgs>? _routeAggregations;

        /// <summary>
        /// List of routes to be aggregated
        /// </summary>
        public InputList<Inputs.PolicyBGPConfigRouteAggregationArgs> RouteAggregations
        {
            get => _routeAggregations ?? (_routeAggregations = new InputList<Inputs.PolicyBGPConfigRouteAggregationArgs>());
            set => _routeAggregations = value;
        }

        /// <summary>
        /// Site Path for this BGP config
        /// </summary>
        [Input("sitePath", required: true)]
        public Input<string> SitePath { get; set; } = null!;

        [Input("tags")]
        private InputList<Inputs.PolicyBGPConfigTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyBGPConfigTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyBGPConfigTagArgs>());
            set => _tags = value;
        }

        public PolicyBGPConfigArgs()
        {
        }
    }

    public sealed class PolicyBGPConfigState : Pulumi.ResourceArgs
    {
        /// <summary>
        /// Flag to enable ECMP
        /// </summary>
        [Input("ecmp")]
        public Input<bool>? Ecmp { get; set; }

        /// <summary>
        /// Flag to enable BGP configuration
        /// </summary>
        [Input("enabled")]
        public Input<bool>? Enabled { get; set; }

        /// <summary>
        /// Gateway for this BGP config
        /// </summary>
        [Input("gatewayPath")]
        public Input<string>? GatewayPath { get; set; }

        /// <summary>
        /// BGP Graceful Restart Configuration Mode
        /// </summary>
        [Input("gracefulRestartMode")]
        public Input<string>? GracefulRestartMode { get; set; }

        /// <summary>
        /// BGP Stale Route Timer
        /// </summary>
        [Input("gracefulRestartStaleRouteTimer")]
        public Input<int>? GracefulRestartStaleRouteTimer { get; set; }

        /// <summary>
        /// BGP Graceful Restart Timer
        /// </summary>
        [Input("gracefulRestartTimer")]
        public Input<int>? GracefulRestartTimer { get; set; }

        /// <summary>
        /// Enable inter SR IBGP configuration
        /// </summary>
        [Input("interSrIbgp")]
        public Input<bool>? InterSrIbgp { get; set; }

        /// <summary>
        /// BGP AS number in ASPLAIN/ASDOT Format
        /// </summary>
        [Input("localAsNum")]
        public Input<string>? LocalAsNum { get; set; }

        /// <summary>
        /// Flag to enable BGP multipath relax option
        /// </summary>
        [Input("multipathRelax")]
        public Input<bool>? MultipathRelax { get; set; }

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

        [Input("routeAggregations")]
        private InputList<Inputs.PolicyBGPConfigRouteAggregationGetArgs>? _routeAggregations;

        /// <summary>
        /// List of routes to be aggregated
        /// </summary>
        public InputList<Inputs.PolicyBGPConfigRouteAggregationGetArgs> RouteAggregations
        {
            get => _routeAggregations ?? (_routeAggregations = new InputList<Inputs.PolicyBGPConfigRouteAggregationGetArgs>());
            set => _routeAggregations = value;
        }

        /// <summary>
        /// Site Path for this BGP config
        /// </summary>
        [Input("sitePath")]
        public Input<string>? SitePath { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicyBGPConfigTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.PolicyBGPConfigTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyBGPConfigTagGetArgs>());
            set => _tags = value;
        }

        public PolicyBGPConfigState()
        {
        }
    }
}
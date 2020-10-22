// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyTier0GatewayVrfConfigGetArgs : Pulumi.ResourceArgs
    {
        [Input("evpnTransitVni")]
        public Input<int>? EvpnTransitVni { get; set; }

        [Input("gatewayPath", required: true)]
        public Input<string> GatewayPath { get; set; } = null!;

        [Input("path")]
        public Input<string>? Path { get; set; }

        [Input("routeDistinguisher")]
        public Input<string>? RouteDistinguisher { get; set; }

        [Input("routeTarget")]
        public Input<Inputs.PolicyTier0GatewayVrfConfigRouteTargetGetArgs>? RouteTarget { get; set; }

        [Input("tags")]
        private InputList<Inputs.PolicyTier0GatewayVrfConfigTagGetArgs>? _tags;
        public InputList<Inputs.PolicyTier0GatewayVrfConfigTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.PolicyTier0GatewayVrfConfigTagGetArgs>());
            set => _tags = value;
        }

        public PolicyTier0GatewayVrfConfigGetArgs()
        {
        }
    }
}

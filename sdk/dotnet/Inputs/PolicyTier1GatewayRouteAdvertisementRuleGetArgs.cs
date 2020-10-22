// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyTier1GatewayRouteAdvertisementRuleGetArgs : Pulumi.ResourceArgs
    {
        [Input("action")]
        public Input<string>? Action { get; set; }

        [Input("name", required: true)]
        public Input<string> Name { get; set; } = null!;

        [Input("prefixOperator")]
        public Input<string>? PrefixOperator { get; set; }

        [Input("routeAdvertisementTypes")]
        private InputList<string>? _routeAdvertisementTypes;
        public InputList<string> RouteAdvertisementTypes
        {
            get => _routeAdvertisementTypes ?? (_routeAdvertisementTypes = new InputList<string>());
            set => _routeAdvertisementTypes = value;
        }

        [Input("subnets", required: true)]
        private InputList<string>? _subnets;
        public InputList<string> Subnets
        {
            get => _subnets ?? (_subnets = new InputList<string>());
            set => _subnets = value;
        }

        public PolicyTier1GatewayRouteAdvertisementRuleGetArgs()
        {
        }
    }
}

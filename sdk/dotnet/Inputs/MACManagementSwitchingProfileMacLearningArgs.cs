// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class MACManagementSwitchingProfileMacLearningArgs : Pulumi.ResourceArgs
    {
        [Input("enabled")]
        public Input<bool>? Enabled { get; set; }

        [Input("limit")]
        public Input<int>? Limit { get; set; }

        [Input("limitPolicy")]
        public Input<string>? LimitPolicy { get; set; }

        [Input("unicastFloodingAllowed")]
        public Input<bool>? UnicastFloodingAllowed { get; set; }

        public MACManagementSwitchingProfileMacLearningArgs()
        {
        }
    }
}
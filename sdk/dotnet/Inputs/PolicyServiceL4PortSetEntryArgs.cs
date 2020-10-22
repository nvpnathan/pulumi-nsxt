// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyServiceL4PortSetEntryArgs : Pulumi.ResourceArgs
    {
        [Input("description")]
        public Input<string>? Description { get; set; }

        [Input("destinationPorts")]
        private InputList<string>? _destinationPorts;
        public InputList<string> DestinationPorts
        {
            get => _destinationPorts ?? (_destinationPorts = new InputList<string>());
            set => _destinationPorts = value;
        }

        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("protocol", required: true)]
        public Input<string> Protocol { get; set; } = null!;

        [Input("sourcePorts")]
        private InputList<string>? _sourcePorts;
        public InputList<string> SourcePorts
        {
            get => _sourcePorts ?? (_sourcePorts = new InputList<string>());
            set => _sourcePorts = value;
        }

        public PolicyServiceL4PortSetEntryArgs()
        {
        }
    }
}

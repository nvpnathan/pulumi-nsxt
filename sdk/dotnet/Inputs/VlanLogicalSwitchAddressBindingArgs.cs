// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class VlanLogicalSwitchAddressBindingArgs : Pulumi.ResourceArgs
    {
        [Input("ipAddress")]
        public Input<string>? IpAddress { get; set; }

        [Input("macAddress")]
        public Input<string>? MacAddress { get; set; }

        [Input("vlan")]
        public Input<int>? Vlan { get; set; }

        public VlanLogicalSwitchAddressBindingArgs()
        {
        }
    }
}

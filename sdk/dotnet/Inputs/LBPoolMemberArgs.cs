// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class LBPoolMemberArgs : Pulumi.ResourceArgs
    {
        [Input("adminState")]
        public Input<string>? AdminState { get; set; }

        [Input("backupMember")]
        public Input<bool>? BackupMember { get; set; }

        [Input("displayName")]
        public Input<string>? DisplayName { get; set; }

        [Input("ipAddress", required: true)]
        public Input<string> IpAddress { get; set; } = null!;

        [Input("maxConcurrentConnections")]
        public Input<int>? MaxConcurrentConnections { get; set; }

        [Input("port")]
        public Input<string>? Port { get; set; }

        [Input("weight")]
        public Input<int>? Weight { get; set; }

        public LBPoolMemberArgs()
        {
        }
    }
}
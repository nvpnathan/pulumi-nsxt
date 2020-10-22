// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt.Inputs
{

    public sealed class PolicyContextProfileAppIdSubAttributeArgs : Pulumi.ResourceArgs
    {
        [Input("cifsSmbVersions")]
        private InputList<string>? _cifsSmbVersions;
        public InputList<string> CifsSmbVersions
        {
            get => _cifsSmbVersions ?? (_cifsSmbVersions = new InputList<string>());
            set => _cifsSmbVersions = value;
        }

        [Input("tlsCipherSuites")]
        private InputList<string>? _tlsCipherSuites;
        public InputList<string> TlsCipherSuites
        {
            get => _tlsCipherSuites ?? (_tlsCipherSuites = new InputList<string>());
            set => _tlsCipherSuites = value;
        }

        [Input("tlsVersions")]
        private InputList<string>? _tlsVersions;
        public InputList<string> TlsVersions
        {
            get => _tlsVersions ?? (_tlsVersions = new InputList<string>());
            set => _tlsVersions = value;
        }

        public PolicyContextProfileAppIdSubAttributeArgs()
        {
        }
    }
}
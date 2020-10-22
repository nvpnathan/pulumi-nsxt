// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class LBServerSSLProfile : Pulumi.CustomResource
    {
        /// <summary>
        /// Supported SSL cipher list
        /// </summary>
        [Output("ciphers")]
        public Output<ImmutableArray<string>> Ciphers { get; private set; } = null!;

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
        /// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
        /// protocols is insecure
        /// </summary>
        [Output("isSecure")]
        public Output<bool> IsSecure { get; private set; } = null!;

        /// <summary>
        /// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
        /// disabled by default
        /// </summary>
        [Output("protocols")]
        public Output<ImmutableArray<string>> Protocols { get; private set; } = null!;

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Output("revision")]
        public Output<int> Revision { get; private set; } = null!;

        /// <summary>
        /// Reuse previously negotiated security parameters during handshake
        /// </summary>
        [Output("sessionCacheEnabled")]
        public Output<bool?> SessionCacheEnabled { get; private set; } = null!;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        [Output("tags")]
        public Output<ImmutableArray<Outputs.LBServerSSLProfileTag>> Tags { get; private set; } = null!;


        /// <summary>
        /// Create a LBServerSSLProfile resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LBServerSSLProfile(string name, LBServerSSLProfileArgs? args = null, CustomResourceOptions? options = null)
            : base("nsxt:index/lBServerSSLProfile:LBServerSSLProfile", name, args ?? new LBServerSSLProfileArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LBServerSSLProfile(string name, Input<string> id, LBServerSSLProfileState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/lBServerSSLProfile:LBServerSSLProfile", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LBServerSSLProfile resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LBServerSSLProfile Get(string name, Input<string> id, LBServerSSLProfileState? state = null, CustomResourceOptions? options = null)
        {
            return new LBServerSSLProfile(name, id, state, options);
        }
    }

    public sealed class LBServerSSLProfileArgs : Pulumi.ResourceArgs
    {
        [Input("ciphers")]
        private InputList<string>? _ciphers;

        /// <summary>
        /// Supported SSL cipher list
        /// </summary>
        public InputList<string> Ciphers
        {
            get => _ciphers ?? (_ciphers = new InputList<string>());
            set => _ciphers = value;
        }

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

        [Input("protocols")]
        private InputList<string>? _protocols;

        /// <summary>
        /// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
        /// disabled by default
        /// </summary>
        public InputList<string> Protocols
        {
            get => _protocols ?? (_protocols = new InputList<string>());
            set => _protocols = value;
        }

        /// <summary>
        /// Reuse previously negotiated security parameters during handshake
        /// </summary>
        [Input("sessionCacheEnabled")]
        public Input<bool>? SessionCacheEnabled { get; set; }

        [Input("tags")]
        private InputList<Inputs.LBServerSSLProfileTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBServerSSLProfileTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBServerSSLProfileTagArgs>());
            set => _tags = value;
        }

        public LBServerSSLProfileArgs()
        {
        }
    }

    public sealed class LBServerSSLProfileState : Pulumi.ResourceArgs
    {
        [Input("ciphers")]
        private InputList<string>? _ciphers;

        /// <summary>
        /// Supported SSL cipher list
        /// </summary>
        public InputList<string> Ciphers
        {
            get => _ciphers ?? (_ciphers = new InputList<string>());
            set => _ciphers = value;
        }

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
        /// This flag is set to true when all the ciphers and protocols are secure. It is set to false when one of the ciphers or
        /// protocols is insecure
        /// </summary>
        [Input("isSecure")]
        public Input<bool>? IsSecure { get; set; }

        [Input("protocols")]
        private InputList<string>? _protocols;

        /// <summary>
        /// SSL versions TLS1.1 and TLS1.2 are supported and enabled by default. SSLv2, SSLv3, and TLS1.0 are supported, but
        /// disabled by default
        /// </summary>
        public InputList<string> Protocols
        {
            get => _protocols ?? (_protocols = new InputList<string>());
            set => _protocols = value;
        }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        /// <summary>
        /// Reuse previously negotiated security parameters during handshake
        /// </summary>
        [Input("sessionCacheEnabled")]
        public Input<bool>? SessionCacheEnabled { get; set; }

        [Input("tags")]
        private InputList<Inputs.LBServerSSLProfileTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBServerSSLProfileTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBServerSSLProfileTagGetArgs>());
            set => _tags = value;
        }

        public LBServerSSLProfileState()
        {
        }
    }
}

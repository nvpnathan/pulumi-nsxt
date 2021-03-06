// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Nsxt
{
    public partial class LBHTTPResponseRewriteRule : Pulumi.CustomResource
    {
        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        [Output("cookieConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleCookieCondition>> CookieConditions { get; private set; } = null!;

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
        /// Header to replace original header in outgoing message
        /// </summary>
        [Output("headerRewriteAction")]
        public Output<Outputs.LBHTTPResponseRewriteRuleHeaderRewriteAction> HeaderRewriteAction { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on IP settings of the message
        /// </summary>
        [Output("ipConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleIpCondition>> IpConditions { get; private set; } = null!;

        /// <summary>
        /// Strategy when multiple match conditions are specified in one rule (ANY vs ALL)
        /// </summary>
        [Output("matchStrategy")]
        public Output<string?> MatchStrategy { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on http request method
        /// </summary>
        [Output("methodConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleMethodCondition>> MethodConditions { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        [Output("requestHeaderConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleRequestHeaderCondition>> RequestHeaderConditions { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        [Output("responseHeaderConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleResponseHeaderCondition>> ResponseHeaderConditions { get; private set; } = null!;

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
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleTag>> Tags { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on TCP settings of the message
        /// </summary>
        [Output("tcpConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleTcpCondition>> TcpConditions { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on http request URI arguments (query string)
        /// </summary>
        [Output("uriArgumentsConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleUriArgumentsCondition>> UriArgumentsConditions { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on http request URI
        /// </summary>
        [Output("uriConditions")]
        public Output<ImmutableArray<Outputs.LBHTTPResponseRewriteRuleUriCondition>> UriConditions { get; private set; } = null!;

        /// <summary>
        /// Rule condition based on http request version
        /// </summary>
        [Output("versionCondition")]
        public Output<Outputs.LBHTTPResponseRewriteRuleVersionCondition?> VersionCondition { get; private set; } = null!;


        /// <summary>
        /// Create a LBHTTPResponseRewriteRule resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public LBHTTPResponseRewriteRule(string name, LBHTTPResponseRewriteRuleArgs args, CustomResourceOptions? options = null)
            : base("nsxt:index/lBHTTPResponseRewriteRule:LBHTTPResponseRewriteRule", name, args ?? new LBHTTPResponseRewriteRuleArgs(), MakeResourceOptions(options, ""))
        {
        }

        private LBHTTPResponseRewriteRule(string name, Input<string> id, LBHTTPResponseRewriteRuleState? state = null, CustomResourceOptions? options = null)
            : base("nsxt:index/lBHTTPResponseRewriteRule:LBHTTPResponseRewriteRule", name, state, MakeResourceOptions(options, id))
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
        /// Get an existing LBHTTPResponseRewriteRule resource's state with the given name, ID, and optional extra
        /// properties used to qualify the lookup.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resulting resource.</param>
        /// <param name="id">The unique provider ID of the resource to lookup.</param>
        /// <param name="state">Any extra arguments used during the lookup.</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public static LBHTTPResponseRewriteRule Get(string name, Input<string> id, LBHTTPResponseRewriteRuleState? state = null, CustomResourceOptions? options = null)
        {
            return new LBHTTPResponseRewriteRule(name, id, state, options);
        }
    }

    public sealed class LBHTTPResponseRewriteRuleArgs : Pulumi.ResourceArgs
    {
        [Input("cookieConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleCookieConditionArgs>? _cookieConditions;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleCookieConditionArgs> CookieConditions
        {
            get => _cookieConditions ?? (_cookieConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleCookieConditionArgs>());
            set => _cookieConditions = value;
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
        /// Header to replace original header in outgoing message
        /// </summary>
        [Input("headerRewriteAction", required: true)]
        public Input<Inputs.LBHTTPResponseRewriteRuleHeaderRewriteActionArgs> HeaderRewriteAction { get; set; } = null!;

        [Input("ipConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleIpConditionArgs>? _ipConditions;

        /// <summary>
        /// Rule condition based on IP settings of the message
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleIpConditionArgs> IpConditions
        {
            get => _ipConditions ?? (_ipConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleIpConditionArgs>());
            set => _ipConditions = value;
        }

        /// <summary>
        /// Strategy when multiple match conditions are specified in one rule (ANY vs ALL)
        /// </summary>
        [Input("matchStrategy")]
        public Input<string>? MatchStrategy { get; set; }

        [Input("methodConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleMethodConditionArgs>? _methodConditions;

        /// <summary>
        /// Rule condition based on http request method
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleMethodConditionArgs> MethodConditions
        {
            get => _methodConditions ?? (_methodConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleMethodConditionArgs>());
            set => _methodConditions = value;
        }

        [Input("requestHeaderConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleRequestHeaderConditionArgs>? _requestHeaderConditions;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleRequestHeaderConditionArgs> RequestHeaderConditions
        {
            get => _requestHeaderConditions ?? (_requestHeaderConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleRequestHeaderConditionArgs>());
            set => _requestHeaderConditions = value;
        }

        [Input("responseHeaderConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleResponseHeaderConditionArgs>? _responseHeaderConditions;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleResponseHeaderConditionArgs> ResponseHeaderConditions
        {
            get => _responseHeaderConditions ?? (_responseHeaderConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleResponseHeaderConditionArgs>());
            set => _responseHeaderConditions = value;
        }

        [Input("tags")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleTagArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleTagArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBHTTPResponseRewriteRuleTagArgs>());
            set => _tags = value;
        }

        [Input("tcpConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleTcpConditionArgs>? _tcpConditions;

        /// <summary>
        /// Rule condition based on TCP settings of the message
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleTcpConditionArgs> TcpConditions
        {
            get => _tcpConditions ?? (_tcpConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleTcpConditionArgs>());
            set => _tcpConditions = value;
        }

        [Input("uriArgumentsConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleUriArgumentsConditionArgs>? _uriArgumentsConditions;

        /// <summary>
        /// Rule condition based on http request URI arguments (query string)
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleUriArgumentsConditionArgs> UriArgumentsConditions
        {
            get => _uriArgumentsConditions ?? (_uriArgumentsConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleUriArgumentsConditionArgs>());
            set => _uriArgumentsConditions = value;
        }

        [Input("uriConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleUriConditionArgs>? _uriConditions;

        /// <summary>
        /// Rule condition based on http request URI
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleUriConditionArgs> UriConditions
        {
            get => _uriConditions ?? (_uriConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleUriConditionArgs>());
            set => _uriConditions = value;
        }

        /// <summary>
        /// Rule condition based on http request version
        /// </summary>
        [Input("versionCondition")]
        public Input<Inputs.LBHTTPResponseRewriteRuleVersionConditionArgs>? VersionCondition { get; set; }

        public LBHTTPResponseRewriteRuleArgs()
        {
        }
    }

    public sealed class LBHTTPResponseRewriteRuleState : Pulumi.ResourceArgs
    {
        [Input("cookieConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleCookieConditionGetArgs>? _cookieConditions;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleCookieConditionGetArgs> CookieConditions
        {
            get => _cookieConditions ?? (_cookieConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleCookieConditionGetArgs>());
            set => _cookieConditions = value;
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
        /// Header to replace original header in outgoing message
        /// </summary>
        [Input("headerRewriteAction")]
        public Input<Inputs.LBHTTPResponseRewriteRuleHeaderRewriteActionGetArgs>? HeaderRewriteAction { get; set; }

        [Input("ipConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleIpConditionGetArgs>? _ipConditions;

        /// <summary>
        /// Rule condition based on IP settings of the message
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleIpConditionGetArgs> IpConditions
        {
            get => _ipConditions ?? (_ipConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleIpConditionGetArgs>());
            set => _ipConditions = value;
        }

        /// <summary>
        /// Strategy when multiple match conditions are specified in one rule (ANY vs ALL)
        /// </summary>
        [Input("matchStrategy")]
        public Input<string>? MatchStrategy { get; set; }

        [Input("methodConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleMethodConditionGetArgs>? _methodConditions;

        /// <summary>
        /// Rule condition based on http request method
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleMethodConditionGetArgs> MethodConditions
        {
            get => _methodConditions ?? (_methodConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleMethodConditionGetArgs>());
            set => _methodConditions = value;
        }

        [Input("requestHeaderConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleRequestHeaderConditionGetArgs>? _requestHeaderConditions;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleRequestHeaderConditionGetArgs> RequestHeaderConditions
        {
            get => _requestHeaderConditions ?? (_requestHeaderConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleRequestHeaderConditionGetArgs>());
            set => _requestHeaderConditions = value;
        }

        [Input("responseHeaderConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleResponseHeaderConditionGetArgs>? _responseHeaderConditions;

        /// <summary>
        /// Rule condition based on http header
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleResponseHeaderConditionGetArgs> ResponseHeaderConditions
        {
            get => _responseHeaderConditions ?? (_responseHeaderConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleResponseHeaderConditionGetArgs>());
            set => _responseHeaderConditions = value;
        }

        /// <summary>
        /// The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
        /// changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
        /// operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        /// </summary>
        [Input("revision")]
        public Input<int>? Revision { get; set; }

        [Input("tags")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleTagGetArgs>? _tags;

        /// <summary>
        /// Set of opaque identifiers meaningful to the user
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleTagGetArgs> Tags
        {
            get => _tags ?? (_tags = new InputList<Inputs.LBHTTPResponseRewriteRuleTagGetArgs>());
            set => _tags = value;
        }

        [Input("tcpConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleTcpConditionGetArgs>? _tcpConditions;

        /// <summary>
        /// Rule condition based on TCP settings of the message
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleTcpConditionGetArgs> TcpConditions
        {
            get => _tcpConditions ?? (_tcpConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleTcpConditionGetArgs>());
            set => _tcpConditions = value;
        }

        [Input("uriArgumentsConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleUriArgumentsConditionGetArgs>? _uriArgumentsConditions;

        /// <summary>
        /// Rule condition based on http request URI arguments (query string)
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleUriArgumentsConditionGetArgs> UriArgumentsConditions
        {
            get => _uriArgumentsConditions ?? (_uriArgumentsConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleUriArgumentsConditionGetArgs>());
            set => _uriArgumentsConditions = value;
        }

        [Input("uriConditions")]
        private InputList<Inputs.LBHTTPResponseRewriteRuleUriConditionGetArgs>? _uriConditions;

        /// <summary>
        /// Rule condition based on http request URI
        /// </summary>
        public InputList<Inputs.LBHTTPResponseRewriteRuleUriConditionGetArgs> UriConditions
        {
            get => _uriConditions ?? (_uriConditions = new InputList<Inputs.LBHTTPResponseRewriteRuleUriConditionGetArgs>());
            set => _uriConditions = value;
        }

        /// <summary>
        /// Rule condition based on http request version
        /// </summary>
        [Input("versionCondition")]
        public Input<Inputs.LBHTTPResponseRewriteRuleVersionConditionGetArgs>? VersionCondition { get; set; }

        public LBHTTPResponseRewriteRuleState()
        {
        }
    }
}

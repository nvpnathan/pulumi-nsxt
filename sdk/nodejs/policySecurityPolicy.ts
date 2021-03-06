// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicySecurityPolicy extends pulumi.CustomResource {
    /**
     * Get an existing PolicySecurityPolicy resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicySecurityPolicyState, opts?: pulumi.CustomResourceOptions): PolicySecurityPolicy {
        return new PolicySecurityPolicy(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policySecurityPolicy:PolicySecurityPolicy';

    /**
     * Returns true if the given object is an instance of PolicySecurityPolicy.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicySecurityPolicy {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicySecurityPolicy.__pulumiType;
    }

    /**
     * Category
     */
    public readonly category!: pulumi.Output<string>;
    /**
     * Comments for security policy lock/unlock
     */
    public readonly comments!: pulumi.Output<string | undefined>;
    /**
     * Description for this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * Display name for this resource
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The domain name to use for resources. If not specified 'default' is used
     */
    public readonly domain!: pulumi.Output<string | undefined>;
    /**
     * Indicates whether a security policy should be locked. If locked by a user, no other user would be able to modify this
     * policy
     */
    public readonly locked!: pulumi.Output<boolean | undefined>;
    /**
     * NSX ID for this resource
     */
    public readonly nsxId!: pulumi.Output<string>;
    /**
     * Policy path for this resource
     */
    public /*out*/ readonly path!: pulumi.Output<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * List of rules in the section
     */
    public readonly rules!: pulumi.Output<outputs.PolicySecurityPolicyRule[] | undefined>;
    /**
     * The list of group paths where the rules in this policy will get applied
     */
    public readonly scopes!: pulumi.Output<string[] | undefined>;
    /**
     * This field is used to resolve conflicts between security policies across domains
     */
    public readonly sequenceNumber!: pulumi.Output<number | undefined>;
    /**
     * When it is stateful, the state of the network connects are tracked and a stateful packet inspection is performed
     */
    public readonly stateful!: pulumi.Output<boolean | undefined>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicySecurityPolicyTag[] | undefined>;
    /**
     * Ensures that a 3 way TCP handshake is done before the data packets are sent
     */
    public readonly tcpStrict!: pulumi.Output<boolean>;

    /**
     * Create a PolicySecurityPolicy resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicySecurityPolicyArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicySecurityPolicyArgs | PolicySecurityPolicyState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicySecurityPolicyState | undefined;
            inputs["category"] = state ? state.category : undefined;
            inputs["comments"] = state ? state.comments : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["domain"] = state ? state.domain : undefined;
            inputs["locked"] = state ? state.locked : undefined;
            inputs["nsxId"] = state ? state.nsxId : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["rules"] = state ? state.rules : undefined;
            inputs["scopes"] = state ? state.scopes : undefined;
            inputs["sequenceNumber"] = state ? state.sequenceNumber : undefined;
            inputs["stateful"] = state ? state.stateful : undefined;
            inputs["tags"] = state ? state.tags : undefined;
            inputs["tcpStrict"] = state ? state.tcpStrict : undefined;
        } else {
            const args = argsOrState as PolicySecurityPolicyArgs | undefined;
            if (!args || args.category === undefined) {
                throw new Error("Missing required property 'category'");
            }
            if (!args || args.displayName === undefined) {
                throw new Error("Missing required property 'displayName'");
            }
            inputs["category"] = args ? args.category : undefined;
            inputs["comments"] = args ? args.comments : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["domain"] = args ? args.domain : undefined;
            inputs["locked"] = args ? args.locked : undefined;
            inputs["nsxId"] = args ? args.nsxId : undefined;
            inputs["rules"] = args ? args.rules : undefined;
            inputs["scopes"] = args ? args.scopes : undefined;
            inputs["sequenceNumber"] = args ? args.sequenceNumber : undefined;
            inputs["stateful"] = args ? args.stateful : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["tcpStrict"] = args ? args.tcpStrict : undefined;
            inputs["path"] = undefined /*out*/;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(PolicySecurityPolicy.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicySecurityPolicy resources.
 */
export interface PolicySecurityPolicyState {
    /**
     * Category
     */
    readonly category?: pulumi.Input<string>;
    /**
     * Comments for security policy lock/unlock
     */
    readonly comments?: pulumi.Input<string>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * The domain name to use for resources. If not specified 'default' is used
     */
    readonly domain?: pulumi.Input<string>;
    /**
     * Indicates whether a security policy should be locked. If locked by a user, no other user would be able to modify this
     * policy
     */
    readonly locked?: pulumi.Input<boolean>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Policy path for this resource
     */
    readonly path?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * List of rules in the section
     */
    readonly rules?: pulumi.Input<pulumi.Input<inputs.PolicySecurityPolicyRule>[]>;
    /**
     * The list of group paths where the rules in this policy will get applied
     */
    readonly scopes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * This field is used to resolve conflicts between security policies across domains
     */
    readonly sequenceNumber?: pulumi.Input<number>;
    /**
     * When it is stateful, the state of the network connects are tracked and a stateful packet inspection is performed
     */
    readonly stateful?: pulumi.Input<boolean>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicySecurityPolicyTag>[]>;
    /**
     * Ensures that a 3 way TCP handshake is done before the data packets are sent
     */
    readonly tcpStrict?: pulumi.Input<boolean>;
}

/**
 * The set of arguments for constructing a PolicySecurityPolicy resource.
 */
export interface PolicySecurityPolicyArgs {
    /**
     * Category
     */
    readonly category: pulumi.Input<string>;
    /**
     * Comments for security policy lock/unlock
     */
    readonly comments?: pulumi.Input<string>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName: pulumi.Input<string>;
    /**
     * The domain name to use for resources. If not specified 'default' is used
     */
    readonly domain?: pulumi.Input<string>;
    /**
     * Indicates whether a security policy should be locked. If locked by a user, no other user would be able to modify this
     * policy
     */
    readonly locked?: pulumi.Input<boolean>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * List of rules in the section
     */
    readonly rules?: pulumi.Input<pulumi.Input<inputs.PolicySecurityPolicyRule>[]>;
    /**
     * The list of group paths where the rules in this policy will get applied
     */
    readonly scopes?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * This field is used to resolve conflicts between security policies across domains
     */
    readonly sequenceNumber?: pulumi.Input<number>;
    /**
     * When it is stateful, the state of the network connects are tracked and a stateful packet inspection is performed
     */
    readonly stateful?: pulumi.Input<boolean>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicySecurityPolicyTag>[]>;
    /**
     * Ensures that a 3 way TCP handshake is done before the data packets are sent
     */
    readonly tcpStrict?: pulumi.Input<boolean>;
}

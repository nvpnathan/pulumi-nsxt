// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicyGroup extends pulumi.CustomResource {
    /**
     * Get an existing PolicyGroup resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicyGroupState, opts?: pulumi.CustomResourceOptions): PolicyGroup {
        return new PolicyGroup(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policyGroup:PolicyGroup';

    /**
     * Returns true if the given object is an instance of PolicyGroup.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicyGroup {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicyGroup.__pulumiType;
    }

    /**
     * A conjunction applied to 2 sets of criteria.
     */
    public readonly conjunctions!: pulumi.Output<outputs.PolicyGroupConjunction[] | undefined>;
    /**
     * Criteria to determine Group membership
     */
    public readonly criterias!: pulumi.Output<outputs.PolicyGroupCriteria[] | undefined>;
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
     * Extended criteria to determine group membership. extended_criteria is implicitly "AND" with criteria
     */
    public readonly extendedCriteria!: pulumi.Output<outputs.PolicyGroupExtendedCriteria | undefined>;
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
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicyGroupTag[] | undefined>;

    /**
     * Create a PolicyGroup resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicyGroupArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicyGroupArgs | PolicyGroupState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicyGroupState | undefined;
            inputs["conjunctions"] = state ? state.conjunctions : undefined;
            inputs["criterias"] = state ? state.criterias : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["domain"] = state ? state.domain : undefined;
            inputs["extendedCriteria"] = state ? state.extendedCriteria : undefined;
            inputs["nsxId"] = state ? state.nsxId : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as PolicyGroupArgs | undefined;
            if (!args || args.displayName === undefined) {
                throw new Error("Missing required property 'displayName'");
            }
            inputs["conjunctions"] = args ? args.conjunctions : undefined;
            inputs["criterias"] = args ? args.criterias : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["domain"] = args ? args.domain : undefined;
            inputs["extendedCriteria"] = args ? args.extendedCriteria : undefined;
            inputs["nsxId"] = args ? args.nsxId : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["path"] = undefined /*out*/;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(PolicyGroup.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicyGroup resources.
 */
export interface PolicyGroupState {
    /**
     * A conjunction applied to 2 sets of criteria.
     */
    readonly conjunctions?: pulumi.Input<pulumi.Input<inputs.PolicyGroupConjunction>[]>;
    /**
     * Criteria to determine Group membership
     */
    readonly criterias?: pulumi.Input<pulumi.Input<inputs.PolicyGroupCriteria>[]>;
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
     * Extended criteria to determine group membership. extended_criteria is implicitly "AND" with criteria
     */
    readonly extendedCriteria?: pulumi.Input<inputs.PolicyGroupExtendedCriteria>;
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
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyGroupTag>[]>;
}

/**
 * The set of arguments for constructing a PolicyGroup resource.
 */
export interface PolicyGroupArgs {
    /**
     * A conjunction applied to 2 sets of criteria.
     */
    readonly conjunctions?: pulumi.Input<pulumi.Input<inputs.PolicyGroupConjunction>[]>;
    /**
     * Criteria to determine Group membership
     */
    readonly criterias?: pulumi.Input<pulumi.Input<inputs.PolicyGroupCriteria>[]>;
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
     * Extended criteria to determine group membership. extended_criteria is implicitly "AND" with criteria
     */
    readonly extendedCriteria?: pulumi.Input<inputs.PolicyGroupExtendedCriteria>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyGroupTag>[]>;
}

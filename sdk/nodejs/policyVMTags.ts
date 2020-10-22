// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicyVMTags extends pulumi.CustomResource {
    /**
     * Get an existing PolicyVMTags resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicyVMTagsState, opts?: pulumi.CustomResourceOptions): PolicyVMTags {
        return new PolicyVMTags(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policyVMTags:PolicyVMTags';

    /**
     * Returns true if the given object is an instance of PolicyVMTags.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicyVMTags {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicyVMTags.__pulumiType;
    }

    /**
     * Instance id
     */
    public readonly instanceId!: pulumi.Output<string>;
    /**
     * Tag specificiation for corresponding segment port
     */
    public readonly ports!: pulumi.Output<outputs.PolicyVMTagsPort[] | undefined>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicyVMTagsTag[] | undefined>;

    /**
     * Create a PolicyVMTags resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicyVMTagsArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicyVMTagsArgs | PolicyVMTagsState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicyVMTagsState | undefined;
            inputs["instanceId"] = state ? state.instanceId : undefined;
            inputs["ports"] = state ? state.ports : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as PolicyVMTagsArgs | undefined;
            if (!args || args.instanceId === undefined) {
                throw new Error("Missing required property 'instanceId'");
            }
            inputs["instanceId"] = args ? args.instanceId : undefined;
            inputs["ports"] = args ? args.ports : undefined;
            inputs["tags"] = args ? args.tags : undefined;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(PolicyVMTags.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicyVMTags resources.
 */
export interface PolicyVMTagsState {
    /**
     * Instance id
     */
    readonly instanceId?: pulumi.Input<string>;
    /**
     * Tag specificiation for corresponding segment port
     */
    readonly ports?: pulumi.Input<pulumi.Input<inputs.PolicyVMTagsPort>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyVMTagsTag>[]>;
}

/**
 * The set of arguments for constructing a PolicyVMTags resource.
 */
export interface PolicyVMTagsArgs {
    /**
     * Instance id
     */
    readonly instanceId: pulumi.Input<string>;
    /**
     * Tag specificiation for corresponding segment port
     */
    readonly ports?: pulumi.Input<pulumi.Input<inputs.PolicyVMTagsPort>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyVMTagsTag>[]>;
}
// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicyIPAddressAllocation extends pulumi.CustomResource {
    /**
     * Get an existing PolicyIPAddressAllocation resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicyIPAddressAllocationState, opts?: pulumi.CustomResourceOptions): PolicyIPAddressAllocation {
        return new PolicyIPAddressAllocation(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policyIPAddressAllocation:PolicyIPAddressAllocation';

    /**
     * Returns true if the given object is an instance of PolicyIPAddressAllocation.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicyIPAddressAllocation {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicyIPAddressAllocation.__pulumiType;
    }

    /**
     * The IP allocated. If unspecified any free IP will be allocated.
     */
    public readonly allocationIp!: pulumi.Output<string>;
    /**
     * Description for this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * Display name for this resource
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * NSX ID for this resource
     */
    public readonly nsxId!: pulumi.Output<string>;
    /**
     * Policy path for this resource
     */
    public /*out*/ readonly path!: pulumi.Output<string>;
    /**
     * The path of the IP Pool for this allocation
     */
    public readonly poolPath!: pulumi.Output<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicyIPAddressAllocationTag[] | undefined>;

    /**
     * Create a PolicyIPAddressAllocation resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicyIPAddressAllocationArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicyIPAddressAllocationArgs | PolicyIPAddressAllocationState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicyIPAddressAllocationState | undefined;
            inputs["allocationIp"] = state ? state.allocationIp : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["nsxId"] = state ? state.nsxId : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["poolPath"] = state ? state.poolPath : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as PolicyIPAddressAllocationArgs | undefined;
            if (!args || args.displayName === undefined) {
                throw new Error("Missing required property 'displayName'");
            }
            if (!args || args.poolPath === undefined) {
                throw new Error("Missing required property 'poolPath'");
            }
            inputs["allocationIp"] = args ? args.allocationIp : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["nsxId"] = args ? args.nsxId : undefined;
            inputs["poolPath"] = args ? args.poolPath : undefined;
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
        super(PolicyIPAddressAllocation.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicyIPAddressAllocation resources.
 */
export interface PolicyIPAddressAllocationState {
    /**
     * The IP allocated. If unspecified any free IP will be allocated.
     */
    readonly allocationIp?: pulumi.Input<string>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Policy path for this resource
     */
    readonly path?: pulumi.Input<string>;
    /**
     * The path of the IP Pool for this allocation
     */
    readonly poolPath?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyIPAddressAllocationTag>[]>;
}

/**
 * The set of arguments for constructing a PolicyIPAddressAllocation resource.
 */
export interface PolicyIPAddressAllocationArgs {
    /**
     * The IP allocated. If unspecified any free IP will be allocated.
     */
    readonly allocationIp?: pulumi.Input<string>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName: pulumi.Input<string>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * The path of the IP Pool for this allocation
     */
    readonly poolPath: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyIPAddressAllocationTag>[]>;
}
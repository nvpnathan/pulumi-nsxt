// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class IPBlock extends pulumi.CustomResource {
    /**
     * Get an existing IPBlock resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: IPBlockState, opts?: pulumi.CustomResourceOptions): IPBlock {
        return new IPBlock(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/iPBlock:IPBlock';

    /**
     * Returns true if the given object is an instance of IPBlock.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is IPBlock {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === IPBlock.__pulumiType;
    }

    /**
     * Represents network address and the prefix length which will be associated with a layer-2 broadcast domain
     */
    public readonly cidr!: pulumi.Output<string>;
    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.IPBlockTag[] | undefined>;

    /**
     * Create a IPBlock resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: IPBlockArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: IPBlockArgs | IPBlockState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as IPBlockState | undefined;
            inputs["cidr"] = state ? state.cidr : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as IPBlockArgs | undefined;
            if (!args || args.cidr === undefined) {
                throw new Error("Missing required property 'cidr'");
            }
            inputs["cidr"] = args ? args.cidr : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(IPBlock.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering IPBlock resources.
 */
export interface IPBlockState {
    /**
     * Represents network address and the prefix length which will be associated with a layer-2 broadcast domain
     */
    readonly cidr?: pulumi.Input<string>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.IPBlockTag>[]>;
}

/**
 * The set of arguments for constructing a IPBlock resource.
 */
export interface IPBlockArgs {
    /**
     * Represents network address and the prefix length which will be associated with a layer-2 broadcast domain
     */
    readonly cidr: pulumi.Input<string>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.IPBlockTag>[]>;
}

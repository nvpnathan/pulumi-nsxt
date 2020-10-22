// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class LBFastTCPApplicationProfile extends pulumi.CustomResource {
    /**
     * Get an existing LBFastTCPApplicationProfile resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: LBFastTCPApplicationProfileState, opts?: pulumi.CustomResourceOptions): LBFastTCPApplicationProfile {
        return new LBFastTCPApplicationProfile(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/lBFastTCPApplicationProfile:LBFastTCPApplicationProfile';

    /**
     * Returns true if the given object is an instance of LBFastTCPApplicationProfile.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is LBFastTCPApplicationProfile {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === LBFastTCPApplicationProfile.__pulumiType;
    }

    /**
     * Timeout in seconds to specify how long a closed TCP connection should be kept for this application before cleaning up
     * the connection
     */
    public readonly closeTimeout!: pulumi.Output<number | undefined>;
    /**
     * Description of this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * A boolean flag which reflects whether flow mirroring is enabled, and all the flows to the bounded virtual server are
     * mirrored to the standby node
     */
    public readonly haFlowMirroring!: pulumi.Output<boolean | undefined>;
    /**
     * Timeout in seconds to specify how long an idle TCP connection in ESTABLISHED state should be kept for this application
     * before cleaning up
     */
    public readonly idleTimeout!: pulumi.Output<number | undefined>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.LBFastTCPApplicationProfileTag[] | undefined>;

    /**
     * Create a LBFastTCPApplicationProfile resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: LBFastTCPApplicationProfileArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: LBFastTCPApplicationProfileArgs | LBFastTCPApplicationProfileState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as LBFastTCPApplicationProfileState | undefined;
            inputs["closeTimeout"] = state ? state.closeTimeout : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["haFlowMirroring"] = state ? state.haFlowMirroring : undefined;
            inputs["idleTimeout"] = state ? state.idleTimeout : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as LBFastTCPApplicationProfileArgs | undefined;
            inputs["closeTimeout"] = args ? args.closeTimeout : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["haFlowMirroring"] = args ? args.haFlowMirroring : undefined;
            inputs["idleTimeout"] = args ? args.idleTimeout : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(LBFastTCPApplicationProfile.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering LBFastTCPApplicationProfile resources.
 */
export interface LBFastTCPApplicationProfileState {
    /**
     * Timeout in seconds to specify how long a closed TCP connection should be kept for this application before cleaning up
     * the connection
     */
    readonly closeTimeout?: pulumi.Input<number>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * A boolean flag which reflects whether flow mirroring is enabled, and all the flows to the bounded virtual server are
     * mirrored to the standby node
     */
    readonly haFlowMirroring?: pulumi.Input<boolean>;
    /**
     * Timeout in seconds to specify how long an idle TCP connection in ESTABLISHED state should be kept for this application
     * before cleaning up
     */
    readonly idleTimeout?: pulumi.Input<number>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LBFastTCPApplicationProfileTag>[]>;
}

/**
 * The set of arguments for constructing a LBFastTCPApplicationProfile resource.
 */
export interface LBFastTCPApplicationProfileArgs {
    /**
     * Timeout in seconds to specify how long a closed TCP connection should be kept for this application before cleaning up
     * the connection
     */
    readonly closeTimeout?: pulumi.Input<number>;
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * A boolean flag which reflects whether flow mirroring is enabled, and all the flows to the bounded virtual server are
     * mirrored to the standby node
     */
    readonly haFlowMirroring?: pulumi.Input<boolean>;
    /**
     * Timeout in seconds to specify how long an idle TCP connection in ESTABLISHED state should be kept for this application
     * before cleaning up
     */
    readonly idleTimeout?: pulumi.Input<number>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.LBFastTCPApplicationProfileTag>[]>;
}

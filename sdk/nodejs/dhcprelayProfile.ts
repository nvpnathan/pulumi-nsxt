// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class DHCPRelayProfile extends pulumi.CustomResource {
    /**
     * Get an existing DHCPRelayProfile resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: DHCPRelayProfileState, opts?: pulumi.CustomResourceOptions): DHCPRelayProfile {
        return new DHCPRelayProfile(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/dHCPRelayProfile:DHCPRelayProfile';

    /**
     * Returns true if the given object is an instance of DHCPRelayProfile.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is DHCPRelayProfile {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === DHCPRelayProfile.__pulumiType;
    }

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
     * Set of dhcp relay server addresses
     */
    public readonly serverAddresses!: pulumi.Output<string[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.DHCPRelayProfileTag[] | undefined>;

    /**
     * Create a DHCPRelayProfile resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: DHCPRelayProfileArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: DHCPRelayProfileArgs | DHCPRelayProfileState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as DHCPRelayProfileState | undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["serverAddresses"] = state ? state.serverAddresses : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as DHCPRelayProfileArgs | undefined;
            if (!args || args.serverAddresses === undefined) {
                throw new Error("Missing required property 'serverAddresses'");
            }
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["serverAddresses"] = args ? args.serverAddresses : undefined;
            inputs["tags"] = args ? args.tags : undefined;
            inputs["revision"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(DHCPRelayProfile.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering DHCPRelayProfile resources.
 */
export interface DHCPRelayProfileState {
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
     * Set of dhcp relay server addresses
     */
    readonly serverAddresses?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.DHCPRelayProfileTag>[]>;
}

/**
 * The set of arguments for constructing a DHCPRelayProfile resource.
 */
export interface DHCPRelayProfileArgs {
    /**
     * Description of this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * The display name of this resource. Defaults to ID if not set
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Set of dhcp relay server addresses
     */
    readonly serverAddresses: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.DHCPRelayProfileTag>[]>;
}

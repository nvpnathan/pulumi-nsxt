// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicyTier0GatewayHAVIPConfig extends pulumi.CustomResource {
    /**
     * Get an existing PolicyTier0GatewayHAVIPConfig resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicyTier0GatewayHAVIPConfigState, opts?: pulumi.CustomResourceOptions): PolicyTier0GatewayHAVIPConfig {
        return new PolicyTier0GatewayHAVIPConfig(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policyTier0GatewayHAVIPConfig:PolicyTier0GatewayHAVIPConfig';

    /**
     * Returns true if the given object is an instance of PolicyTier0GatewayHAVIPConfig.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicyTier0GatewayHAVIPConfig {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicyTier0GatewayHAVIPConfig.__pulumiType;
    }

    /**
     * Tier0 HA VIP Config
     */
    public readonly configs!: pulumi.Output<outputs.PolicyTier0GatewayHAVIPConfigConfig[]>;
    /**
     * Id of associated Gateway Locale Service on NSX
     */
    public /*out*/ readonly localeServiceId!: pulumi.Output<string>;
    /**
     * Id of associated Tier0 Gateway on NSX
     */
    public /*out*/ readonly tier0Id!: pulumi.Output<string>;

    /**
     * Create a PolicyTier0GatewayHAVIPConfig resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicyTier0GatewayHAVIPConfigArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicyTier0GatewayHAVIPConfigArgs | PolicyTier0GatewayHAVIPConfigState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicyTier0GatewayHAVIPConfigState | undefined;
            inputs["configs"] = state ? state.configs : undefined;
            inputs["localeServiceId"] = state ? state.localeServiceId : undefined;
            inputs["tier0Id"] = state ? state.tier0Id : undefined;
        } else {
            const args = argsOrState as PolicyTier0GatewayHAVIPConfigArgs | undefined;
            if (!args || args.configs === undefined) {
                throw new Error("Missing required property 'configs'");
            }
            inputs["configs"] = args ? args.configs : undefined;
            inputs["localeServiceId"] = undefined /*out*/;
            inputs["tier0Id"] = undefined /*out*/;
        }
        if (!opts) {
            opts = {}
        }

        if (!opts.version) {
            opts.version = utilities.getVersion();
        }
        super(PolicyTier0GatewayHAVIPConfig.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicyTier0GatewayHAVIPConfig resources.
 */
export interface PolicyTier0GatewayHAVIPConfigState {
    /**
     * Tier0 HA VIP Config
     */
    readonly configs?: pulumi.Input<pulumi.Input<inputs.PolicyTier0GatewayHAVIPConfigConfig>[]>;
    /**
     * Id of associated Gateway Locale Service on NSX
     */
    readonly localeServiceId?: pulumi.Input<string>;
    /**
     * Id of associated Tier0 Gateway on NSX
     */
    readonly tier0Id?: pulumi.Input<string>;
}

/**
 * The set of arguments for constructing a PolicyTier0GatewayHAVIPConfig resource.
 */
export interface PolicyTier0GatewayHAVIPConfigArgs {
    /**
     * Tier0 HA VIP Config
     */
    readonly configs: pulumi.Input<pulumi.Input<inputs.PolicyTier0GatewayHAVIPConfigConfig>[]>;
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getPolicyTier1Gateway(args?: GetPolicyTier1GatewayArgs, opts?: pulumi.InvokeOptions): Promise<GetPolicyTier1GatewayResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("nsxt:index/getPolicyTier1Gateway:getPolicyTier1Gateway", {
        "description": args.description,
        "displayName": args.displayName,
        "edgeClusterPath": args.edgeClusterPath,
        "id": args.id,
    }, opts);
}

/**
 * A collection of arguments for invoking getPolicyTier1Gateway.
 */
export interface GetPolicyTier1GatewayArgs {
    readonly description?: string;
    readonly displayName?: string;
    readonly edgeClusterPath?: string;
    readonly id?: string;
}

/**
 * A collection of values returned by getPolicyTier1Gateway.
 */
export interface GetPolicyTier1GatewayResult {
    readonly description: string;
    readonly displayName: string;
    readonly edgeClusterPath: string;
    readonly id: string;
    readonly path: string;
}

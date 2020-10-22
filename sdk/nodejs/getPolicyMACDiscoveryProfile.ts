// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getPolicyMACDiscoveryProfile(args?: GetPolicyMACDiscoveryProfileArgs, opts?: pulumi.InvokeOptions): Promise<GetPolicyMACDiscoveryProfileResult> {
    args = args || {};
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("nsxt:index/getPolicyMACDiscoveryProfile:getPolicyMACDiscoveryProfile", {
        "description": args.description,
        "displayName": args.displayName,
        "id": args.id,
    }, opts);
}

/**
 * A collection of arguments for invoking getPolicyMACDiscoveryProfile.
 */
export interface GetPolicyMACDiscoveryProfileArgs {
    readonly description?: string;
    readonly displayName?: string;
    readonly id?: string;
}

/**
 * A collection of values returned by getPolicyMACDiscoveryProfile.
 */
export interface GetPolicyMACDiscoveryProfileResult {
    readonly description: string;
    readonly displayName: string;
    readonly id: string;
    readonly path: string;
}

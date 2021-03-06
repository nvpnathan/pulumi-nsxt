// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export function getPolicyEdgeNode(args: GetPolicyEdgeNodeArgs, opts?: pulumi.InvokeOptions): Promise<GetPolicyEdgeNodeResult> {
    if (!opts) {
        opts = {}
    }

    if (!opts.version) {
        opts.version = utilities.getVersion();
    }
    return pulumi.runtime.invoke("nsxt:index/getPolicyEdgeNode:getPolicyEdgeNode", {
        "description": args.description,
        "displayName": args.displayName,
        "edgeClusterPath": args.edgeClusterPath,
        "id": args.id,
        "memberIndex": args.memberIndex,
    }, opts);
}

/**
 * A collection of arguments for invoking getPolicyEdgeNode.
 */
export interface GetPolicyEdgeNodeArgs {
    readonly description?: string;
    readonly displayName?: string;
    readonly edgeClusterPath: string;
    readonly id?: string;
    readonly memberIndex?: number;
}

/**
 * A collection of values returned by getPolicyEdgeNode.
 */
export interface GetPolicyEdgeNodeResult {
    readonly description: string;
    readonly displayName: string;
    readonly edgeClusterPath: string;
    readonly id: string;
    readonly memberIndex?: number;
    readonly path: string;
}

// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as inputs from "./types/input";
import * as outputs from "./types/output";
import * as utilities from "./utilities";

export class PolicyLBVirtualServer extends pulumi.CustomResource {
    /**
     * Get an existing PolicyLBVirtualServer resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state Any extra arguments used during the lookup.
     * @param opts Optional settings to control the behavior of the CustomResource.
     */
    public static get(name: string, id: pulumi.Input<pulumi.ID>, state?: PolicyLBVirtualServerState, opts?: pulumi.CustomResourceOptions): PolicyLBVirtualServer {
        return new PolicyLBVirtualServer(name, <any>state, { ...opts, id: id });
    }

    /** @internal */
    public static readonly __pulumiType = 'nsxt:index/policyLBVirtualServer:PolicyLBVirtualServer';

    /**
     * Returns true if the given object is an instance of PolicyLBVirtualServer.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is PolicyLBVirtualServer {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === PolicyLBVirtualServer.__pulumiType;
    }

    /**
     * IP access list control for filtering the connections from clients
     */
    public readonly accessListControl!: pulumi.Output<outputs.PolicyLBVirtualServerAccessListControl | undefined>;
    /**
     * If enabled, all connections/requests sent to virtual server are logged to the access log file
     */
    public readonly accessLogEnabled!: pulumi.Output<boolean | undefined>;
    /**
     * Application profile for this virtual server
     */
    public readonly applicationProfilePath!: pulumi.Output<string>;
    /**
     * This setting is used when load balancer terminates client SSL connection
     */
    public readonly clientSsl!: pulumi.Output<outputs.PolicyLBVirtualServerClientSsl | undefined>;
    /**
     * Default pool member ports when member port is not defined
     */
    public readonly defaultPoolMemberPorts!: pulumi.Output<string[] | undefined>;
    /**
     * Description for this resource
     */
    public readonly description!: pulumi.Output<string | undefined>;
    /**
     * Display name for this resource
     */
    public readonly displayName!: pulumi.Output<string>;
    /**
     * Flag to enable Virtual Server
     */
    public readonly enabled!: pulumi.Output<boolean | undefined>;
    /**
     * Virtual Server IP address
     */
    public readonly ipAddress!: pulumi.Output<string>;
    /**
     * Flag to log significant events in access log, if access log is enabed
     */
    public readonly logSignificantEventOnly!: pulumi.Output<boolean | undefined>;
    /**
     * To ensure one virtual server does not over consume resources, connections to a virtual server can be capped.
     */
    public readonly maxConcurrentConnections!: pulumi.Output<number | undefined>;
    /**
     * To ensure one virtual server does not over consume resources, connections to a member can be rate limited.
     */
    public readonly maxNewConnectionRate!: pulumi.Output<number | undefined>;
    /**
     * NSX ID for this resource
     */
    public readonly nsxId!: pulumi.Output<string>;
    /**
     * Policy path for this resource
     */
    public /*out*/ readonly path!: pulumi.Output<string>;
    /**
     * Path to persistence profile allowing related client connections to be sent to the same backend server.
     */
    public readonly persistenceProfilePath!: pulumi.Output<string | undefined>;
    /**
     * Path for Load Balancer Pool
     */
    public readonly poolPath!: pulumi.Output<string | undefined>;
    /**
     * Virtual Server ports
     */
    public readonly ports!: pulumi.Output<string[]>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    public /*out*/ readonly revision!: pulumi.Output<number>;
    /**
     * This setting is used when load balancer establishes connection to the backend server
     */
    public readonly serverSsl!: pulumi.Output<outputs.PolicyLBVirtualServerServerSsl | undefined>;
    /**
     * Virtual Server can be associated with Load Balancer Service
     */
    public readonly servicePath!: pulumi.Output<string | undefined>;
    /**
     * When load balancer can not select server in default pool or pool in rules, the request would be served by sorry pool
     */
    public readonly sorryPoolPath!: pulumi.Output<string | undefined>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    public readonly tags!: pulumi.Output<outputs.PolicyLBVirtualServerTag[] | undefined>;

    /**
     * Create a PolicyLBVirtualServer resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args: PolicyLBVirtualServerArgs, opts?: pulumi.CustomResourceOptions)
    constructor(name: string, argsOrState?: PolicyLBVirtualServerArgs | PolicyLBVirtualServerState, opts?: pulumi.CustomResourceOptions) {
        let inputs: pulumi.Inputs = {};
        if (opts && opts.id) {
            const state = argsOrState as PolicyLBVirtualServerState | undefined;
            inputs["accessListControl"] = state ? state.accessListControl : undefined;
            inputs["accessLogEnabled"] = state ? state.accessLogEnabled : undefined;
            inputs["applicationProfilePath"] = state ? state.applicationProfilePath : undefined;
            inputs["clientSsl"] = state ? state.clientSsl : undefined;
            inputs["defaultPoolMemberPorts"] = state ? state.defaultPoolMemberPorts : undefined;
            inputs["description"] = state ? state.description : undefined;
            inputs["displayName"] = state ? state.displayName : undefined;
            inputs["enabled"] = state ? state.enabled : undefined;
            inputs["ipAddress"] = state ? state.ipAddress : undefined;
            inputs["logSignificantEventOnly"] = state ? state.logSignificantEventOnly : undefined;
            inputs["maxConcurrentConnections"] = state ? state.maxConcurrentConnections : undefined;
            inputs["maxNewConnectionRate"] = state ? state.maxNewConnectionRate : undefined;
            inputs["nsxId"] = state ? state.nsxId : undefined;
            inputs["path"] = state ? state.path : undefined;
            inputs["persistenceProfilePath"] = state ? state.persistenceProfilePath : undefined;
            inputs["poolPath"] = state ? state.poolPath : undefined;
            inputs["ports"] = state ? state.ports : undefined;
            inputs["revision"] = state ? state.revision : undefined;
            inputs["serverSsl"] = state ? state.serverSsl : undefined;
            inputs["servicePath"] = state ? state.servicePath : undefined;
            inputs["sorryPoolPath"] = state ? state.sorryPoolPath : undefined;
            inputs["tags"] = state ? state.tags : undefined;
        } else {
            const args = argsOrState as PolicyLBVirtualServerArgs | undefined;
            if (!args || args.applicationProfilePath === undefined) {
                throw new Error("Missing required property 'applicationProfilePath'");
            }
            if (!args || args.displayName === undefined) {
                throw new Error("Missing required property 'displayName'");
            }
            if (!args || args.ipAddress === undefined) {
                throw new Error("Missing required property 'ipAddress'");
            }
            if (!args || args.ports === undefined) {
                throw new Error("Missing required property 'ports'");
            }
            inputs["accessListControl"] = args ? args.accessListControl : undefined;
            inputs["accessLogEnabled"] = args ? args.accessLogEnabled : undefined;
            inputs["applicationProfilePath"] = args ? args.applicationProfilePath : undefined;
            inputs["clientSsl"] = args ? args.clientSsl : undefined;
            inputs["defaultPoolMemberPorts"] = args ? args.defaultPoolMemberPorts : undefined;
            inputs["description"] = args ? args.description : undefined;
            inputs["displayName"] = args ? args.displayName : undefined;
            inputs["enabled"] = args ? args.enabled : undefined;
            inputs["ipAddress"] = args ? args.ipAddress : undefined;
            inputs["logSignificantEventOnly"] = args ? args.logSignificantEventOnly : undefined;
            inputs["maxConcurrentConnections"] = args ? args.maxConcurrentConnections : undefined;
            inputs["maxNewConnectionRate"] = args ? args.maxNewConnectionRate : undefined;
            inputs["nsxId"] = args ? args.nsxId : undefined;
            inputs["persistenceProfilePath"] = args ? args.persistenceProfilePath : undefined;
            inputs["poolPath"] = args ? args.poolPath : undefined;
            inputs["ports"] = args ? args.ports : undefined;
            inputs["serverSsl"] = args ? args.serverSsl : undefined;
            inputs["servicePath"] = args ? args.servicePath : undefined;
            inputs["sorryPoolPath"] = args ? args.sorryPoolPath : undefined;
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
        super(PolicyLBVirtualServer.__pulumiType, name, inputs, opts);
    }
}

/**
 * Input properties used for looking up and filtering PolicyLBVirtualServer resources.
 */
export interface PolicyLBVirtualServerState {
    /**
     * IP access list control for filtering the connections from clients
     */
    readonly accessListControl?: pulumi.Input<inputs.PolicyLBVirtualServerAccessListControl>;
    /**
     * If enabled, all connections/requests sent to virtual server are logged to the access log file
     */
    readonly accessLogEnabled?: pulumi.Input<boolean>;
    /**
     * Application profile for this virtual server
     */
    readonly applicationProfilePath?: pulumi.Input<string>;
    /**
     * This setting is used when load balancer terminates client SSL connection
     */
    readonly clientSsl?: pulumi.Input<inputs.PolicyLBVirtualServerClientSsl>;
    /**
     * Default pool member ports when member port is not defined
     */
    readonly defaultPoolMemberPorts?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName?: pulumi.Input<string>;
    /**
     * Flag to enable Virtual Server
     */
    readonly enabled?: pulumi.Input<boolean>;
    /**
     * Virtual Server IP address
     */
    readonly ipAddress?: pulumi.Input<string>;
    /**
     * Flag to log significant events in access log, if access log is enabed
     */
    readonly logSignificantEventOnly?: pulumi.Input<boolean>;
    /**
     * To ensure one virtual server does not over consume resources, connections to a virtual server can be capped.
     */
    readonly maxConcurrentConnections?: pulumi.Input<number>;
    /**
     * To ensure one virtual server does not over consume resources, connections to a member can be rate limited.
     */
    readonly maxNewConnectionRate?: pulumi.Input<number>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Policy path for this resource
     */
    readonly path?: pulumi.Input<string>;
    /**
     * Path to persistence profile allowing related client connections to be sent to the same backend server.
     */
    readonly persistenceProfilePath?: pulumi.Input<string>;
    /**
     * Path for Load Balancer Pool
     */
    readonly poolPath?: pulumi.Input<string>;
    /**
     * Virtual Server ports
     */
    readonly ports?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
     * changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
     * operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
     */
    readonly revision?: pulumi.Input<number>;
    /**
     * This setting is used when load balancer establishes connection to the backend server
     */
    readonly serverSsl?: pulumi.Input<inputs.PolicyLBVirtualServerServerSsl>;
    /**
     * Virtual Server can be associated with Load Balancer Service
     */
    readonly servicePath?: pulumi.Input<string>;
    /**
     * When load balancer can not select server in default pool or pool in rules, the request would be served by sorry pool
     */
    readonly sorryPoolPath?: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyLBVirtualServerTag>[]>;
}

/**
 * The set of arguments for constructing a PolicyLBVirtualServer resource.
 */
export interface PolicyLBVirtualServerArgs {
    /**
     * IP access list control for filtering the connections from clients
     */
    readonly accessListControl?: pulumi.Input<inputs.PolicyLBVirtualServerAccessListControl>;
    /**
     * If enabled, all connections/requests sent to virtual server are logged to the access log file
     */
    readonly accessLogEnabled?: pulumi.Input<boolean>;
    /**
     * Application profile for this virtual server
     */
    readonly applicationProfilePath: pulumi.Input<string>;
    /**
     * This setting is used when load balancer terminates client SSL connection
     */
    readonly clientSsl?: pulumi.Input<inputs.PolicyLBVirtualServerClientSsl>;
    /**
     * Default pool member ports when member port is not defined
     */
    readonly defaultPoolMemberPorts?: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * Description for this resource
     */
    readonly description?: pulumi.Input<string>;
    /**
     * Display name for this resource
     */
    readonly displayName: pulumi.Input<string>;
    /**
     * Flag to enable Virtual Server
     */
    readonly enabled?: pulumi.Input<boolean>;
    /**
     * Virtual Server IP address
     */
    readonly ipAddress: pulumi.Input<string>;
    /**
     * Flag to log significant events in access log, if access log is enabed
     */
    readonly logSignificantEventOnly?: pulumi.Input<boolean>;
    /**
     * To ensure one virtual server does not over consume resources, connections to a virtual server can be capped.
     */
    readonly maxConcurrentConnections?: pulumi.Input<number>;
    /**
     * To ensure one virtual server does not over consume resources, connections to a member can be rate limited.
     */
    readonly maxNewConnectionRate?: pulumi.Input<number>;
    /**
     * NSX ID for this resource
     */
    readonly nsxId?: pulumi.Input<string>;
    /**
     * Path to persistence profile allowing related client connections to be sent to the same backend server.
     */
    readonly persistenceProfilePath?: pulumi.Input<string>;
    /**
     * Path for Load Balancer Pool
     */
    readonly poolPath?: pulumi.Input<string>;
    /**
     * Virtual Server ports
     */
    readonly ports: pulumi.Input<pulumi.Input<string>[]>;
    /**
     * This setting is used when load balancer establishes connection to the backend server
     */
    readonly serverSsl?: pulumi.Input<inputs.PolicyLBVirtualServerServerSsl>;
    /**
     * Virtual Server can be associated with Load Balancer Service
     */
    readonly servicePath?: pulumi.Input<string>;
    /**
     * When load balancer can not select server in default pool or pool in rules, the request would be served by sorry pool
     */
    readonly sorryPoolPath?: pulumi.Input<string>;
    /**
     * Set of opaque identifiers meaningful to the user
     */
    readonly tags?: pulumi.Input<pulumi.Input<inputs.PolicyLBVirtualServerTag>[]>;
}
# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class PolicyNatRule(pulumi.CustomResource):
    action: pulumi.Output[str]
    """
    The action for the NAT Rule
    """
    description: pulumi.Output[str]
    """
    Description for this resource
    """
    destination_networks: pulumi.Output[list]
    """
    The destination network(s) for the NAT Rule
    """
    display_name: pulumi.Output[str]
    """
    Display name for this resource
    """
    enabled: pulumi.Output[bool]
    """
    Enable/disable the rule
    """
    firewall_match: pulumi.Output[str]
    """
    Firewall match flag
    """
    gateway_path: pulumi.Output[str]
    """
    The NSX-T Policy path to the Tier0 or Tier1 Gateway for this resource
    """
    logging: pulumi.Output[bool]
    """
    Enable/disable the logging of rule
    """
    nsx_id: pulumi.Output[str]
    """
    NSX ID for this resource
    """
    path: pulumi.Output[str]
    """
    Policy path for this resource
    """
    revision: pulumi.Output[float]
    """
    The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
    changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
    operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
    """
    rule_priority: pulumi.Output[float]
    """
    The sequence_number decides the rule_priority of a NAT rule. Valid range [0-2147483647]
    """
    scopes: pulumi.Output[list]
    """
    Policy paths to interfaces or labels where the NAT Rule is enforced
    """
    service: pulumi.Output[str]
    """
    Policy path of Service on which the NAT rule will be applied
    """
    source_networks: pulumi.Output[list]
    """
    The source network(s) for the NAT Rule
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    translated_networks: pulumi.Output[list]
    """
    The translated network(s) for the NAT Rule
    """
    translated_ports: pulumi.Output[str]
    """
    Port number or port range. DNAT only
    """
    def __init__(__self__, resource_name, opts=None, action=None, description=None, destination_networks=None, display_name=None, enabled=None, firewall_match=None, gateway_path=None, logging=None, nsx_id=None, rule_priority=None, scopes=None, service=None, source_networks=None, tags=None, translated_networks=None, translated_ports=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a PolicyNatRule resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] action: The action for the NAT Rule
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[list] destination_networks: The destination network(s) for the NAT Rule
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[bool] enabled: Enable/disable the rule
        :param pulumi.Input[str] firewall_match: Firewall match flag
        :param pulumi.Input[str] gateway_path: The NSX-T Policy path to the Tier0 or Tier1 Gateway for this resource
        :param pulumi.Input[bool] logging: Enable/disable the logging of rule
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[float] rule_priority: The sequence_number decides the rule_priority of a NAT rule. Valid range [0-2147483647]
        :param pulumi.Input[list] scopes: Policy paths to interfaces or labels where the NAT Rule is enforced
        :param pulumi.Input[str] service: Policy path of Service on which the NAT rule will be applied
        :param pulumi.Input[list] source_networks: The source network(s) for the NAT Rule
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[list] translated_networks: The translated network(s) for the NAT Rule
        :param pulumi.Input[str] translated_ports: Port number or port range. DNAT only

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        if __name__ is not None:
            warnings.warn("explicit use of __name__ is deprecated", DeprecationWarning)
            resource_name = __name__
        if __opts__ is not None:
            warnings.warn("explicit use of __opts__ is deprecated, use 'opts' instead", DeprecationWarning)
            opts = __opts__
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = utilities.get_version()
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = dict()

            if action is None:
                raise TypeError("Missing required property 'action'")
            __props__['action'] = action
            __props__['description'] = description
            __props__['destination_networks'] = destination_networks
            if display_name is None:
                raise TypeError("Missing required property 'display_name'")
            __props__['display_name'] = display_name
            __props__['enabled'] = enabled
            __props__['firewall_match'] = firewall_match
            if gateway_path is None:
                raise TypeError("Missing required property 'gateway_path'")
            __props__['gateway_path'] = gateway_path
            __props__['logging'] = logging
            __props__['nsx_id'] = nsx_id
            __props__['rule_priority'] = rule_priority
            __props__['scopes'] = scopes
            __props__['service'] = service
            __props__['source_networks'] = source_networks
            __props__['tags'] = tags
            if translated_networks is None:
                raise TypeError("Missing required property 'translated_networks'")
            __props__['translated_networks'] = translated_networks
            __props__['translated_ports'] = translated_ports
            __props__['path'] = None
            __props__['revision'] = None
        super(PolicyNatRule, __self__).__init__(
            'nsxt:index/policyNatRule:PolicyNatRule',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, action=None, description=None, destination_networks=None, display_name=None, enabled=None, firewall_match=None, gateway_path=None, logging=None, nsx_id=None, path=None, revision=None, rule_priority=None, scopes=None, service=None, source_networks=None, tags=None, translated_networks=None, translated_ports=None):
        """
        Get an existing PolicyNatRule resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] action: The action for the NAT Rule
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[list] destination_networks: The destination network(s) for the NAT Rule
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[bool] enabled: Enable/disable the rule
        :param pulumi.Input[str] firewall_match: Firewall match flag
        :param pulumi.Input[str] gateway_path: The NSX-T Policy path to the Tier0 or Tier1 Gateway for this resource
        :param pulumi.Input[bool] logging: Enable/disable the logging of rule
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[str] path: Policy path for this resource
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[float] rule_priority: The sequence_number decides the rule_priority of a NAT rule. Valid range [0-2147483647]
        :param pulumi.Input[list] scopes: Policy paths to interfaces or labels where the NAT Rule is enforced
        :param pulumi.Input[str] service: Policy path of Service on which the NAT rule will be applied
        :param pulumi.Input[list] source_networks: The source network(s) for the NAT Rule
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user
        :param pulumi.Input[list] translated_networks: The translated network(s) for the NAT Rule
        :param pulumi.Input[str] translated_ports: Port number or port range. DNAT only

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["action"] = action
        __props__["description"] = description
        __props__["destination_networks"] = destination_networks
        __props__["display_name"] = display_name
        __props__["enabled"] = enabled
        __props__["firewall_match"] = firewall_match
        __props__["gateway_path"] = gateway_path
        __props__["logging"] = logging
        __props__["nsx_id"] = nsx_id
        __props__["path"] = path
        __props__["revision"] = revision
        __props__["rule_priority"] = rule_priority
        __props__["scopes"] = scopes
        __props__["service"] = service
        __props__["source_networks"] = source_networks
        __props__["tags"] = tags
        __props__["translated_networks"] = translated_networks
        __props__["translated_ports"] = translated_ports
        return PolicyNatRule(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop

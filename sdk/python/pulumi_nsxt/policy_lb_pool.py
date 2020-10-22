# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class PolicyLBPool(pulumi.CustomResource):
    active_monitor_path: pulumi.Output[str]
    """
    Active healthcheck is disabled by default and can be enabled using this setting
    """
    algorithm: pulumi.Output[str]
    description: pulumi.Output[str]
    """
    Description for this resource
    """
    display_name: pulumi.Output[str]
    """
    Display name for this resource
    """
    member_group: pulumi.Output[dict]
    """
    Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified

      * `allowIpv4` (`bool`)
      * `allowIpv6` (`bool`)
      * `groupPath` (`str`)
      * `maxIpListSize` (`float`)
      * `port` (`str`)
    """
    members: pulumi.Output[list]
    """
    List of server pool members. Each pool member is identified, typically, by an IP address and a port

      * `admin_state` (`str`)
      * `backupMember` (`bool`)
      * `display_name` (`str`)
      * `ip_address` (`str`)
      * `max_concurrent_connections` (`float`)
      * `port` (`str`)
      * `weight` (`float`)
    """
    min_active_members: pulumi.Output[float]
    nsx_id: pulumi.Output[str]
    """
    NSX ID for this resource
    """
    passive_monitor_path: pulumi.Output[str]
    """
    Policy path for passive health monitor
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
    snat: pulumi.Output[dict]
    """
    SNAT configuration

      * `ipPoolAddresses` (`list`)
      * `type` (`str`)
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    tcp_multiplexing_enabled: pulumi.Output[bool]
    tcp_multiplexing_number: pulumi.Output[float]
    def __init__(__self__, resource_name, opts=None, active_monitor_path=None, algorithm=None, description=None, display_name=None, member_group=None, members=None, min_active_members=None, nsx_id=None, passive_monitor_path=None, snat=None, tags=None, tcp_multiplexing_enabled=None, tcp_multiplexing_number=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a PolicyLBPool resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] active_monitor_path: Active healthcheck is disabled by default and can be enabled using this setting
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[dict] member_group: Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
        :param pulumi.Input[list] members: List of server pool members. Each pool member is identified, typically, by an IP address and a port
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[str] passive_monitor_path: Policy path for passive health monitor
        :param pulumi.Input[dict] snat: SNAT configuration
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **member_group** object supports the following:

          * `allowIpv4` (`pulumi.Input[bool]`)
          * `allowIpv6` (`pulumi.Input[bool]`)
          * `groupPath` (`pulumi.Input[str]`)
          * `maxIpListSize` (`pulumi.Input[float]`)
          * `port` (`pulumi.Input[str]`)

        The **members** object supports the following:

          * `admin_state` (`pulumi.Input[str]`)
          * `backupMember` (`pulumi.Input[bool]`)
          * `display_name` (`pulumi.Input[str]`)
          * `ip_address` (`pulumi.Input[str]`)
          * `max_concurrent_connections` (`pulumi.Input[float]`)
          * `port` (`pulumi.Input[str]`)
          * `weight` (`pulumi.Input[float]`)

        The **snat** object supports the following:

          * `ipPoolAddresses` (`pulumi.Input[list]`)
          * `type` (`pulumi.Input[str]`)

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

            __props__['active_monitor_path'] = active_monitor_path
            __props__['algorithm'] = algorithm
            __props__['description'] = description
            if display_name is None:
                raise TypeError("Missing required property 'display_name'")
            __props__['display_name'] = display_name
            __props__['member_group'] = member_group
            __props__['members'] = members
            __props__['min_active_members'] = min_active_members
            __props__['nsx_id'] = nsx_id
            __props__['passive_monitor_path'] = passive_monitor_path
            __props__['snat'] = snat
            __props__['tags'] = tags
            __props__['tcp_multiplexing_enabled'] = tcp_multiplexing_enabled
            __props__['tcp_multiplexing_number'] = tcp_multiplexing_number
            __props__['path'] = None
            __props__['revision'] = None
        super(PolicyLBPool, __self__).__init__(
            'nsxt:index/policyLBPool:PolicyLBPool',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, active_monitor_path=None, algorithm=None, description=None, display_name=None, member_group=None, members=None, min_active_members=None, nsx_id=None, passive_monitor_path=None, path=None, revision=None, snat=None, tags=None, tcp_multiplexing_enabled=None, tcp_multiplexing_number=None):
        """
        Get an existing PolicyLBPool resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[str] active_monitor_path: Active healthcheck is disabled by default and can be enabled using this setting
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[dict] member_group: Dynamic pool members for the loadbalancing pool. When member group is defined, members setting should not be specified
        :param pulumi.Input[list] members: List of server pool members. Each pool member is identified, typically, by an IP address and a port
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[str] passive_monitor_path: Policy path for passive health monitor
        :param pulumi.Input[str] path: Policy path for this resource
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[dict] snat: SNAT configuration
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **member_group** object supports the following:

          * `allowIpv4` (`pulumi.Input[bool]`)
          * `allowIpv6` (`pulumi.Input[bool]`)
          * `groupPath` (`pulumi.Input[str]`)
          * `maxIpListSize` (`pulumi.Input[float]`)
          * `port` (`pulumi.Input[str]`)

        The **members** object supports the following:

          * `admin_state` (`pulumi.Input[str]`)
          * `backupMember` (`pulumi.Input[bool]`)
          * `display_name` (`pulumi.Input[str]`)
          * `ip_address` (`pulumi.Input[str]`)
          * `max_concurrent_connections` (`pulumi.Input[float]`)
          * `port` (`pulumi.Input[str]`)
          * `weight` (`pulumi.Input[float]`)

        The **snat** object supports the following:

          * `ipPoolAddresses` (`pulumi.Input[list]`)
          * `type` (`pulumi.Input[str]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["active_monitor_path"] = active_monitor_path
        __props__["algorithm"] = algorithm
        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["member_group"] = member_group
        __props__["members"] = members
        __props__["min_active_members"] = min_active_members
        __props__["nsx_id"] = nsx_id
        __props__["passive_monitor_path"] = passive_monitor_path
        __props__["path"] = path
        __props__["revision"] = revision
        __props__["snat"] = snat
        __props__["tags"] = tags
        __props__["tcp_multiplexing_enabled"] = tcp_multiplexing_enabled
        __props__["tcp_multiplexing_number"] = tcp_multiplexing_number
        return PolicyLBPool(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop

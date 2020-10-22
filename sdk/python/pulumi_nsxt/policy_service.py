# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class PolicyService(pulumi.CustomResource):
    algorithm_entries: pulumi.Output[list]
    """
    Algorithm type service entry

      * `algorithm` (`str`)
      * `description` (`str`)
      * `destination_port` (`str`)
      * `display_name` (`str`)
      * `source_ports` (`list`)
    """
    description: pulumi.Output[str]
    """
    Description for this resource
    """
    display_name: pulumi.Output[str]
    """
    Display name for this resource
    """
    ether_type_entries: pulumi.Output[list]
    """
    Ether type service entry

      * `description` (`str`)
      * `display_name` (`str`)
      * `ether_type` (`float`)
    """
    icmp_entries: pulumi.Output[list]
    """
    ICMP type service entry

      * `description` (`str`)
      * `display_name` (`str`)
      * `icmp_code` (`str`)
      * `icmp_type` (`str`)
      * `protocol` (`str`)
    """
    igmp_entries: pulumi.Output[list]
    """
    IGMP type service entry

      * `description` (`str`)
      * `display_name` (`str`)
    """
    ip_protocol_entries: pulumi.Output[list]
    """
    IP Protocol type service entry

      * `description` (`str`)
      * `display_name` (`str`)
      * `protocol` (`float`)
    """
    l4_port_set_entries: pulumi.Output[list]
    """
    L4 port set type service entry

      * `description` (`str`)
      * `destination_ports` (`list`)
      * `display_name` (`str`)
      * `protocol` (`str`)
      * `source_ports` (`list`)
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
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    def __init__(__self__, resource_name, opts=None, algorithm_entries=None, description=None, display_name=None, ether_type_entries=None, icmp_entries=None, igmp_entries=None, ip_protocol_entries=None, l4_port_set_entries=None, nsx_id=None, tags=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a PolicyService resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[list] algorithm_entries: Algorithm type service entry
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[list] ether_type_entries: Ether type service entry
        :param pulumi.Input[list] icmp_entries: ICMP type service entry
        :param pulumi.Input[list] igmp_entries: IGMP type service entry
        :param pulumi.Input[list] ip_protocol_entries: IP Protocol type service entry
        :param pulumi.Input[list] l4_port_set_entries: L4 port set type service entry
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **algorithm_entries** object supports the following:

          * `algorithm` (`pulumi.Input[str]`)
          * `description` (`pulumi.Input[str]`)
          * `destination_port` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `source_ports` (`pulumi.Input[list]`)

        The **ether_type_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `ether_type` (`pulumi.Input[float]`)

        The **icmp_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `icmp_code` (`pulumi.Input[str]`)
          * `icmp_type` (`pulumi.Input[str]`)
          * `protocol` (`pulumi.Input[str]`)

        The **igmp_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)

        The **ip_protocol_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `protocol` (`pulumi.Input[float]`)

        The **l4_port_set_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `destination_ports` (`pulumi.Input[list]`)
          * `display_name` (`pulumi.Input[str]`)
          * `protocol` (`pulumi.Input[str]`)
          * `source_ports` (`pulumi.Input[list]`)

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

            __props__['algorithm_entries'] = algorithm_entries
            __props__['description'] = description
            if display_name is None:
                raise TypeError("Missing required property 'display_name'")
            __props__['display_name'] = display_name
            __props__['ether_type_entries'] = ether_type_entries
            __props__['icmp_entries'] = icmp_entries
            __props__['igmp_entries'] = igmp_entries
            __props__['ip_protocol_entries'] = ip_protocol_entries
            __props__['l4_port_set_entries'] = l4_port_set_entries
            __props__['nsx_id'] = nsx_id
            __props__['tags'] = tags
            __props__['path'] = None
            __props__['revision'] = None
        super(PolicyService, __self__).__init__(
            'nsxt:index/policyService:PolicyService',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, algorithm_entries=None, description=None, display_name=None, ether_type_entries=None, icmp_entries=None, igmp_entries=None, ip_protocol_entries=None, l4_port_set_entries=None, nsx_id=None, path=None, revision=None, tags=None):
        """
        Get an existing PolicyService resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[list] algorithm_entries: Algorithm type service entry
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] display_name: Display name for this resource
        :param pulumi.Input[list] ether_type_entries: Ether type service entry
        :param pulumi.Input[list] icmp_entries: ICMP type service entry
        :param pulumi.Input[list] igmp_entries: IGMP type service entry
        :param pulumi.Input[list] ip_protocol_entries: IP Protocol type service entry
        :param pulumi.Input[list] l4_port_set_entries: L4 port set type service entry
        :param pulumi.Input[str] nsx_id: NSX ID for this resource
        :param pulumi.Input[str] path: Policy path for this resource
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **algorithm_entries** object supports the following:

          * `algorithm` (`pulumi.Input[str]`)
          * `description` (`pulumi.Input[str]`)
          * `destination_port` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `source_ports` (`pulumi.Input[list]`)

        The **ether_type_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `ether_type` (`pulumi.Input[float]`)

        The **icmp_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `icmp_code` (`pulumi.Input[str]`)
          * `icmp_type` (`pulumi.Input[str]`)
          * `protocol` (`pulumi.Input[str]`)

        The **igmp_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)

        The **ip_protocol_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `display_name` (`pulumi.Input[str]`)
          * `protocol` (`pulumi.Input[float]`)

        The **l4_port_set_entries** object supports the following:

          * `description` (`pulumi.Input[str]`)
          * `destination_ports` (`pulumi.Input[list]`)
          * `display_name` (`pulumi.Input[str]`)
          * `protocol` (`pulumi.Input[str]`)
          * `source_ports` (`pulumi.Input[list]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["algorithm_entries"] = algorithm_entries
        __props__["description"] = description
        __props__["display_name"] = display_name
        __props__["ether_type_entries"] = ether_type_entries
        __props__["icmp_entries"] = icmp_entries
        __props__["igmp_entries"] = igmp_entries
        __props__["ip_protocol_entries"] = ip_protocol_entries
        __props__["l4_port_set_entries"] = l4_port_set_entries
        __props__["nsx_id"] = nsx_id
        __props__["path"] = path
        __props__["revision"] = revision
        __props__["tags"] = tags
        return PolicyService(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop

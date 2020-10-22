# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Union
from . import utilities, tables


class PolicyPredefinedSecurityPolicy(pulumi.CustomResource):
    default_rule: pulumi.Output[dict]
    """
    List of default rules

      * `action` (`str`)
      * `description` (`str`)
      * `logLabel` (`str`)
      * `logged` (`bool`)
      * `nsx_id` (`str`)
      * `path` (`str`)
      * `revision` (`float`)
      * `scope` (`str`)
      * `sequence_number` (`float`)
      * `tags` (`list`)
        * `scope` (`str`)
        * `tag` (`str`)
    """
    description: pulumi.Output[str]
    """
    Description for this resource
    """
    path: pulumi.Output[str]
    """
    Path for this Security Policy
    """
    revision: pulumi.Output[float]
    """
    The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
    changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
    operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
    """
    rules: pulumi.Output[list]
    """
    List of rules in the section

      * `action` (`str`)
      * `description` (`str`)
      * `destinationGroups` (`list`)
      * `destinationsExcluded` (`bool`)
      * `direction` (`str`)
      * `disabled` (`bool`)
      * `display_name` (`str`)
      * `ipVersion` (`str`)
      * `logLabel` (`str`)
      * `logged` (`bool`)
      * `notes` (`str`)
      * `nsx_id` (`str`)
      * `profiles` (`list`)
      * `revision` (`float`)
      * `ruleId` (`float`)
      * `scopes` (`list`)
      * `sequence_number` (`float`)
      * `services` (`list`)
      * `sourceGroups` (`list`)
      * `sourcesExcluded` (`bool`)
      * `tags` (`list`)
        * `scope` (`str`)
        * `tag` (`str`)
    """
    tags: pulumi.Output[list]
    """
    Set of opaque identifiers meaningful to the user

      * `scope` (`str`)
      * `tag` (`str`)
    """
    def __init__(__self__, resource_name, opts=None, default_rule=None, description=None, path=None, rules=None, tags=None, __props__=None, __name__=None, __opts__=None):
        """
        Create a PolicyPredefinedSecurityPolicy resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[dict] default_rule: List of default rules
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] path: Path for this Security Policy
        :param pulumi.Input[list] rules: List of rules in the section
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **default_rule** object supports the following:

          * `action` (`pulumi.Input[str]`)
          * `description` (`pulumi.Input[str]`)
          * `logLabel` (`pulumi.Input[str]`)
          * `logged` (`pulumi.Input[bool]`)
          * `nsx_id` (`pulumi.Input[str]`)
          * `path` (`pulumi.Input[str]`)
          * `revision` (`pulumi.Input[float]`)
          * `scope` (`pulumi.Input[str]`)
          * `sequence_number` (`pulumi.Input[float]`)
          * `tags` (`pulumi.Input[list]`)
            * `scope` (`pulumi.Input[str]`)
            * `tag` (`pulumi.Input[str]`)

        The **rules** object supports the following:

          * `action` (`pulumi.Input[str]`)
          * `description` (`pulumi.Input[str]`)
          * `destinationGroups` (`pulumi.Input[list]`)
          * `destinationsExcluded` (`pulumi.Input[bool]`)
          * `direction` (`pulumi.Input[str]`)
          * `disabled` (`pulumi.Input[bool]`)
          * `display_name` (`pulumi.Input[str]`)
          * `ipVersion` (`pulumi.Input[str]`)
          * `logLabel` (`pulumi.Input[str]`)
          * `logged` (`pulumi.Input[bool]`)
          * `notes` (`pulumi.Input[str]`)
          * `nsx_id` (`pulumi.Input[str]`)
          * `profiles` (`pulumi.Input[list]`)
          * `revision` (`pulumi.Input[float]`)
          * `ruleId` (`pulumi.Input[float]`)
          * `scopes` (`pulumi.Input[list]`)
          * `sequence_number` (`pulumi.Input[float]`)
          * `services` (`pulumi.Input[list]`)
          * `sourceGroups` (`pulumi.Input[list]`)
          * `sourcesExcluded` (`pulumi.Input[bool]`)
          * `tags` (`pulumi.Input[list]`)
            * `scope` (`pulumi.Input[str]`)
            * `tag` (`pulumi.Input[str]`)

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

            __props__['default_rule'] = default_rule
            __props__['description'] = description
            if path is None:
                raise TypeError("Missing required property 'path'")
            __props__['path'] = path
            __props__['rules'] = rules
            __props__['tags'] = tags
            __props__['revision'] = None
        super(PolicyPredefinedSecurityPolicy, __self__).__init__(
            'nsxt:index/policyPredefinedSecurityPolicy:PolicyPredefinedSecurityPolicy',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name, id, opts=None, default_rule=None, description=None, path=None, revision=None, rules=None, tags=None):
        """
        Get an existing PolicyPredefinedSecurityPolicy resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param str id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[dict] default_rule: List of default rules
        :param pulumi.Input[str] description: Description for this resource
        :param pulumi.Input[str] path: Path for this Security Policy
        :param pulumi.Input[float] revision: The _revision property describes the current revision of the resource. To prevent clients from overwriting each other's
               changes, PUT operations must include the current _revision of the resource, which clients should obtain by issuing a GET
               operation. If the _revision provided in a PUT request is missing or stale, the operation will be rejected
        :param pulumi.Input[list] rules: List of rules in the section
        :param pulumi.Input[list] tags: Set of opaque identifiers meaningful to the user

        The **default_rule** object supports the following:

          * `action` (`pulumi.Input[str]`)
          * `description` (`pulumi.Input[str]`)
          * `logLabel` (`pulumi.Input[str]`)
          * `logged` (`pulumi.Input[bool]`)
          * `nsx_id` (`pulumi.Input[str]`)
          * `path` (`pulumi.Input[str]`)
          * `revision` (`pulumi.Input[float]`)
          * `scope` (`pulumi.Input[str]`)
          * `sequence_number` (`pulumi.Input[float]`)
          * `tags` (`pulumi.Input[list]`)
            * `scope` (`pulumi.Input[str]`)
            * `tag` (`pulumi.Input[str]`)

        The **rules** object supports the following:

          * `action` (`pulumi.Input[str]`)
          * `description` (`pulumi.Input[str]`)
          * `destinationGroups` (`pulumi.Input[list]`)
          * `destinationsExcluded` (`pulumi.Input[bool]`)
          * `direction` (`pulumi.Input[str]`)
          * `disabled` (`pulumi.Input[bool]`)
          * `display_name` (`pulumi.Input[str]`)
          * `ipVersion` (`pulumi.Input[str]`)
          * `logLabel` (`pulumi.Input[str]`)
          * `logged` (`pulumi.Input[bool]`)
          * `notes` (`pulumi.Input[str]`)
          * `nsx_id` (`pulumi.Input[str]`)
          * `profiles` (`pulumi.Input[list]`)
          * `revision` (`pulumi.Input[float]`)
          * `ruleId` (`pulumi.Input[float]`)
          * `scopes` (`pulumi.Input[list]`)
          * `sequence_number` (`pulumi.Input[float]`)
          * `services` (`pulumi.Input[list]`)
          * `sourceGroups` (`pulumi.Input[list]`)
          * `sourcesExcluded` (`pulumi.Input[bool]`)
          * `tags` (`pulumi.Input[list]`)
            * `scope` (`pulumi.Input[str]`)
            * `tag` (`pulumi.Input[str]`)

        The **tags** object supports the following:

          * `scope` (`pulumi.Input[str]`)
          * `tag` (`pulumi.Input[str]`)
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = dict()

        __props__["default_rule"] = default_rule
        __props__["description"] = description
        __props__["path"] = path
        __props__["revision"] = revision
        __props__["rules"] = rules
        __props__["tags"] = tags
        return PolicyPredefinedSecurityPolicy(resource_name, opts=opts, __props__=__props__)

    def translate_output_property(self, prop):
        return tables._CAMEL_TO_SNAKE_CASE_TABLE.get(prop) or prop

    def translate_input_property(self, prop):
        return tables._SNAKE_TO_CAMEL_CASE_TABLE.get(prop) or prop

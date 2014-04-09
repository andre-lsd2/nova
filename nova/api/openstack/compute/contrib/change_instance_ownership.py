# Copyright 2013 IBM Corp.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import webob.exc

from nova.api.openstack import extensions
from nova import db
from nova import exception
from nova import quota
from nova.openstack.common.gettextutils import _
from nova.openstack.common import log as logging
from keystoneclient.v3 import client
from keystoneclient import access

from oslo.config import cfg
import os
import ast

CONF = cfg.CONF

LOG = logging.getLogger(__name__)

authorize = extensions.extension_authorizer('compute', 'change_instance_ownership')
QUOTAS = quota.QUOTAS

class ChangeInstanceOwnershipController(object):

    def action(self, req, id, body):

        LOG.debug("::PRINT::CHANGE_INSTANCE_OWNERSHIP::ACTION::REQ::%s::ID::%s::BODY::%s::" % (req, id, body))

        context = req.environ['nova.context']
        authorize(context)

        LOG.debug("CONTEXT: %s" % context.to_dict())
        LOG.debug("ALL INSTANCES: %s" % db.instance_get_all(context))
        instance = db.instance_get_by_uuid(context, id)

        owner_id = context.user_id

        #compat_catalog = { 'access': {'token': {'id': ''}}}
        #compat_catalog = None
        #compat_catalog = {'token': {'catalog': context.service_catalog,'methods': ''}}
        #compat_catalog = {'access': {'serviceCatalog': context.service_catalog,'token': {'id': ''}}}

        #LOG.debug("CONTEXT: %s" % context.to_dict())

        x = req.headers.get('X-Service-Catalog', req.headers.get('X_STORAGE_TOKEN'))

        LOG.debug("TESTING AUTH_URL: %s" % x)
        x = ast.literal_eval(x)

        for i in x:
            if i.get("type") == "identity":
                LOG.debug("TESTING IDENTITY: %s" % i)

        auth_url = None

        for i in x:
            if i.get("type") == "identity":
                for j in i.get("endpoints"):
                    if j.get("interface") == "admin":
                        auth_url = j.get("url")


        LOG.debug("TESTING AUTH_URL: %s" % auth_url)

        #sc = access.AccessInfo.factory(None, compat_catalog).service_catalog

        keystone_client = client.Client(token=context.auth_token, auth_url=auth_url)
        #keystone_client = client.Client(token=context.auth_token, auth_url="http://10.1.0.32:5000/v3")

        #LOG.debug("::DEBUG::KEYSTONE::USERS::%s" % keystone_client.users)
        keystone_client.users.list()

        LOG.debug("::DEBUG::CHANGE_INSTANCE_OWNERSHIP::ACTION::BODY::" % body)

        user_id = None
        """if ('user_id' in body):
            LOG.debug("::DEBUG::CHANGE_INSTANCE_OWNERSHIP::ACTION::USER_ID::")
            print("::PRINT::CHANGE_INSTANCE_OWNERSHIP::ACTION::USER_ID::")
            user_id = body['user_id'] if 'user_id' in body else owner_id
        project_id = None
        if ('project_id' in body):
            LOG.debug("::DEBUG::CHANGE_INSTANCE_OWNERSHIP::ACTION::PROJECT_ID::")
            print("::PRINT::CHANGE_INSTANCE_OWNERSHIP::ACTION::PROJECT_ID::")
            project_id = body['project_id'] if 'project_id' in body else instance.project_id

        #user_id = body['user_id'] if 'user_id' in body else owner_id
        #project_id = body['project_id'] if 'project_id' in body else instance.project_id

        LOG.debug("::DEBUG::CHANGE_INSTANCE_OWNERSHIP::ACTION::USER_ID::%s::PROJECT_ID::%s::" % (user_id, project_id))
        print("::PRINT::CHANGE_INSTANCE_OWNERSHIP::ACTION::USER_ID::%s::PROJECT_ID::%s::" % (user_id, project_id))

        if (user_id == owner_id and project_id == instance.project_id):
            raise webob.exc.HTTPBadRequest(explanation="User_id or Project_id were not found in the request body")

        if not self._is_user_in_project(user_id, project_id, keystone_client):
            raise webob.exc.HTTPBadRequest(explanation="User_id or Project_id were not found in the request body")"""

    def _commit(self, instance, context, body, id, user_id=None, project_id=None):
        instance_project_id = instance.project_id
        num_instances = 1
        req_cores = instance.vcpus
        req_ram = instance.memory_mb
        req_fixed_ips = 1
        reservations = self._create_reservation(context,
                                                instances=num_instances,
                                                cores=req_cores,
                                                ram=req_ram,
                                                fixed_ips=req_fixed_ips,
                                                project_id=project_id)
        reservations_del = self._create_reservation(context,
                                                    instances=-num_instances,
                                                    cores=-req_cores,
                                                    ram=-req_ram,
                                                    fixed_ips=-req_fixed_ips,
                                                    project_id=instance_project_id)
        try:
            QUOTAS.commit(context, reservations,
                          project_id=project_id)
            self._update_instance(context, id, body)
        except Exception:
            instance_dict = {}
            instance_dict['project_id'] = instance_project_id
            instance_dict['user_id'] = user_id
            self._update_instance(context, id, instance_dict)
            QUOTAS.rollback(context, reservations)
            QUOTAS.rollback(context, reservations_del)
            msg = _("Error while updating instances.")
            LOG.debug(msg)
            raise webob.exc.HTTPNotFound(explanation=msg)
        else:
            QUOTAS.commit(context, reservations_del)

    def _is_user_in_project(self, user_id, project_id, keystone_client):
        for i in keystone_client.projects.list(user=user_id):
                if project_id == i.id:
                    return project_id

    def _update_instance(self, context, instance_uuid, body):
        try:
            db.instance_update(context, instance_uuid, body, update_cells=True)
        except Exception:
            msg = _("Could not update the instance")
            LOG.debug(msg)
            raise webob.exc.HTTPNotFound(explanation=msg)

        return webob.exc.HTTPAccepted()

    def _create_reservation(self, context, instances, cores, ram, fixed_ips,
                            project_id=None, user_id=None):
         try:
             reservations = QUOTAS.reserve(context,
                                           instances=instances,
                                           cores=cores,
                                           ram=ram,
                                           fixed_ips=fixed_ips,
                                           project_id=project_id,
                                           user_id=user_id)

             return reservations
         except exception.OverQuota as exc:
             quotas = exc.kwargs['quotas']
             overs = exc.kwargs['overs']
             headroom = exc.kwargs['headroom']
             allowed = headroom['instances']
             resource = overs[0]
             used = quotas[resource] - headroom[resource]
             total_allowed = used + headroom[resource]
             requested = dict(num_instances=instances,
                              cores=cores,
                              ram=ram)
             raise exception.TooManyInstances(overs=overs,
                                              req=requested[resource],
                                              used=used,
                                              allowed=total_allowed,
                                              resource=resource)


class Change_instance_ownership(extensions.ExtensionDescriptor):
    """Change instance ownership support."""

    name = "ChangeInstanceOwnership"
    alias = "os-change-instance-ownership"
    namespace = "http://docs.openstack.org/compute/ext/change-instance-ownership/api/v2"
    updated = "2014-03-07T18:00:00-03:00"

    def get_resources(self):
        member_actions = {'action': 'PUT'}
        resources = []
        resource = extensions.ResourceExtension('os-change-instance-ownership',
                                                ChangeInstanceOwnershipController(),
                                                member_actions=member_actions)
        resources.append(resource)
        return resources
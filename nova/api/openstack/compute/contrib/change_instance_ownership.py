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

import ast

LOG = logging.getLogger(__name__)

authorize = extensions.extension_authorizer('compute', 'change_instance_ownership')
QUOTAS = quota.QUOTAS

class ChangeInstanceOwnershipController(object):

    def _get_endpoint_from_catalog(self, catalog, endpoint_type="identity"):
        catalog_eval = ast.literal_eval(catalog)
        for i in catalog_eval:
            if i.get("type") == endpoint_type:
                return i

    def _get_url_from_endpoint(self, endpoint, interface_type="public"):
        for i in endpoint.get("endpoints"):
            if i.get("interface") == interface_type:
                return i.get("url")

    def _get_url_from_catalog(self, catalog, endpoint_type="identity", interface_type="public"):
        endpoint = self._get_endpoint_from_catalog(catalog, endpoint_type)
        return self._get_url_from_endpoint(endpoint, interface_type)

    def _get_field_from_body(self, field, body, default=None):
        user_id = default
        if (field in body):
            user_id = body[field]
        pass

    def action(self, req, id, body):
        context = req.environ['nova.context']
        authorize(context)

        instance = db.instance_get_by_uuid(context, id)
        owner_id = context.user_id

        catalog = req.headers.get('X-Service-Catalog', req.headers.get('X_STORAGE_TOKEN'))

        auth_url = self._get_url_from_catalog(catalog)
        LOG.debug("::DEBUG::AUTH_URL::%s::" % auth_url)
        auth_url = self._replace_url_version(auth_url)
        LOG.debug("::DEBUG::NEW_AUTH_URL::%s::" % auth_url)

        keystone_client = client.Client(token=context.auth_token, endpoint=auth_url)

        user_id = self._get_field_from_body("user_id", body, owner_id)
        project_id = self._get_field_from_body("project_id", body, instance.project_id)

        if ("user_id" not in body and "project_id" not in body):
            raise webob.exc.HTTPBadRequest(explanation="User_id or Project_id were not found in the request body")

        if (user_id == owner_id and project_id == instance.project_id):
            raise webob.exc.HTTPBadRequest(explanation="The User_id and Project_id provided is the same ")

        if not self._is_user_in_project(user_id, project_id, keystone_client):
            raise webob.exc.HTTPBadRequest(explanation="The ")
            #raise webob.exc.HTTPBadRequest(explanation="User_id or Project_id were not found in the request body")

        #self._commit(instance, context, body, id, user_id, project_id)


    def _replace_url_version(self, url, old="2.0", new="3"):
        until = url.find(old)

        return url[:until] + new

    def _delete_keystonev2_from_catalog(self, catalog):
        new_catalog = []
        for i in catalog:
            if i["type"] != "identity":
                new_catalog.append(i)
        return new_catalog

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
        LOG.debug("::DEBUG::USER_ID::%s::PROJECT_ID::%s::" % (user_id, project_id))
        LOG.debug("::DEBUG::PROJECTS_LIST_FOR_USER::%s::" % keystone_client.projects.list(user=user_id))
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
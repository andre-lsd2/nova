# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
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

import webob

import nova.policy

from nova import test

from nova import compute
from nova import context
from nova import db


from nova.api.openstack import compute as openstack_compute
from nova.api.openstack import extensions
from nova.api.openstack import wsgi as os_wsgi

from nova.openstack.common import jsonutils

from nova.tests.api.openstack import fakes

from nova.api.openstack.compute.contrib.change_instance_ownership import ChangeInstanceOwnershipController

from oslo.config import cfg

from keystoneclient.v3 import client

from nova.openstack.common import log as logging

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

class FakeContext(object):
    def __init__(self, project_id, user_id):
        self.is_admin = False
        self.user_id = user_id
        self.project_id = project_id
        self.read_deleted = 'no'
        self.roles = ['owner']

    def elevated(self):
        elevated = self.__class__(self.project_id, self.user_id)
        elevated.is_admin = True
        return elevated

class ChangeInstanceOwnershipTestCase(test.TestCase):

    @classmethod
    def setUpClass(cls):
        super(ChangeInstanceOwnershipTestCase, cls).setUpClass()

        cls.controller = ChangeInstanceOwnershipController()

        cls.keystone = client.Client(username="admin", password="admin", auth_url="http://127.0.0.1:5000/v3/")

        cls.project01 = cls.keystone.projects.create("project01", None)
        cls.user01    = cls.keystone.users.create("user01", project="admin")
        cls.user02    = cls.keystone.users.create("user02", project=cls.project01)

        #self.context = context.RequestContext('fake', 'fake', roles=['member'])
        #cls.context3 = context.RequestContext(cls.user01.id, cls.project01.id)
        cls.context2 = context.get_admin_context()
        cls.context1 = FakeContext(cls.project01.id, cls.user01.id)

    @classmethod
    def tearDownClass(cls):
        super(ChangeInstanceOwnershipTestCase, cls).tearDownClass()

        cls.keystone.projects.delete(cls.project01)
        cls.keystone.users.delete(cls.user01)
        cls.keystone.users.delete(cls.user02)

    def setUp(self):
        super(ChangeInstanceOwnershipTestCase, self).setUp()

    def tearDown(self):
        super(ChangeInstanceOwnershipTestCase, self).tearDown()

    def get_project_id(self, project_name):
        for i in self.keystone.projects.list():
            if i.name == project_name:
                return i.id

    def _create_instance(self, user_id, project_id):
        """Create a test instance."""
        inst = {}
        inst['user_id'] = user_id
        inst['project_id'] = project_id

        return db.instance_create(self.context, inst)

    def _send_server_action_request(self, url, body):
        app = openstack_compute.APIRouter(init_only=('servers',))
        request = webob.Request.blank(url)
        request.method = 'POST'
        request.content_type = 'application/json'
        request.body = jsonutils.dumps(body)

        response = request.get_response(app)
        return response

    def _get_user_by_name(self, name):
        for i in self.keystone.users.list():
            if i.name == name:
                return i

    def _get_project_by_name(self, name):
        for i in self.keystone.projects.list():
            if i.name == name:
                return i

    def test_case_one(self):
        self.context = context.get_admin_context()

        instance = self._create_instance("4c86bbe1f01b4462af3b62e21c2485d1", "090510f9a96049a9a31b1648c45d03d8")

        instance_uuid = instance.uuid
        project_owner_id = instance.project_id

        kwargs = {}
        kwargs['base_url'] = 'http://localhost/v2'
        req = os_wsgi.Request.blank('/%s/os-change-instance-ownership/%s' % (project_owner_id, instance_uuid), kwargs)
        req.environ['nova.context'] = self.context
        body = dict(user_id=self.user02.id)

        self.controller.action(req, id, body)

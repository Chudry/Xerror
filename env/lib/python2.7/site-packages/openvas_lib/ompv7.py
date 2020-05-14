#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This file contains OMPv7 implementation
"""

from openvas_lib import *
from openvas_lib.common import *

__license__ = """
Copyright 2018 - Golismero project

Redistribution and use in source and binary forms, with or without modification
, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
"""

__all__ = ["OMPv7"]


# ------------------------------------------------------------------------------
#
# OMPv7 implementation
#
# ------------------------------------------------------------------------------
class OMPv7(OMP):
	"""
	Internal manager for OpenVAS low level operations.

	..note:
		This class is based in code from the original OpenVAS plugin:

		https://pypi.python.org/pypi/OpenVAS.omplib

	..warning:
		This code is only compatible with OMP 4.0.
	"""

	# ----------------------------------------------------------------------
	def __init__(self, omp_manager):
		"""
		Constructor.

		:param omp_manager: _OMPManager object.
		:type omp_manager: ConnectionManager
		"""
		# Call to super
		super(OMPv7, self).__init__(omp_manager)

	# ----------------------------------------------------------------------
	#
	# PUBLIC METHODS
	#
	# ----------------------------------------------------------------------
	# ----------------------------------------------------------------------
	#
	# METHODS FOR ROLES
	#
	# ----------------------------------------------------------------------
	def get_roles(self):
		"""
		Get roles in OpenVAS.

		:return: a dict with the format: {role_name: role_ID}
		"""

		request = """<get_roles/>"""

		elems = self._manager.make_xml_request(request, xml_result=True)

		m_return = {}

		for x in elems.findall("role"):
			m_return[x.find("name").text.lower()] = x.get("id")

		return m_return

	# ----------------------------------------------------------------------
	#
	# METHODS FOR USER
	#
	# ----------------------------------------------------------------------

	def create_user(self, name, password, role, allow_hosts='0', hosts=[], allow_ifaces='0', ifaces=[]):
		"""
		Creates a new user in OpenVAS.

		:param name: The name of the user to be created.
		:type name: str

		:param password: The password for the user.
		:type password: str

		:param role: A role of the user. If the role not exists in the roles dict then use a user role ID.
		:type role: str

		:param allow_hosts: User access rules: 0 allow all and deny list of hosts (default), 1 deny all and allow list of hosts.
		:type allow_hosts: int

		:param hosts: User access rules: a textual list of hosts (host access).
		:type hosts: list

		:param allow_ifaces: User access rules: 0 allow all and deny list of ifaces (default), 1 deny all and allow list of ifaces.
		:type allow_ifaces: int

		:param ifaces: User access rules: a textual list of ifaces (interfaces access).
		:type ifaces: list

		:return: the ID of the created user (UUID).
		:rtype: str

		"""

		roles = self.get_roles()
		role_id=roles.get(role, 'user')

		request = """<create_user>
				<name>%s</name>
				<password>%s</password>
				<role id="%s"/>""" % (name, password, role_id)

		if hosts:
			request += """<hosts allow="%s">%s</hosts>""" % (allow_hosts, str(",".join(hosts)))

		if ifaces:
			request += """<ifaces allow="%s">%s</ifaces>""" % (allow_ifaces, str(",".join(ifaces)))

		request += """</create_user>"""

		return self._manager.make_xml_request(request, xml_result=True).get("id")

	# ----------------------------------------------------------------------

	def delete_user(self, user_id='', name=''):
		"""
		Delete a user in OpenVAS.

		:param user_id: The ID of the user to be deleted. Overrides name.
		:type user_id: str

		:param name: The name of the user to be deleted.
		:type name: str

		"""

		if user_id:
			request = """<delete_user user_id="%s"/>"""%user_id
		elif name:
			request = """<delete_user name="%s"/>"""%name

		self._manager.make_xml_request(request, xml_result=True)

	# ----------------------------------------------------------------------

	def modify_user(self, user_id, new_name='', password='', role_id='', allow_hosts=None, hosts=[], allow_ifaces=None, ifaces=[]):
		"""
		Modify a user in OpenVAS.

		:param user_id: The ID of the user to be modified.
		:type user_id: str

		:param new_name: The new name for the user.
		:type new_name: str

		:param password: The password for the user.
		:type password: str

		:param role_id: A role of the user.
		:type role_id: str

		:param allow_hosts: User access rules: 0 allow all and deny list of hosts (default), 1 deny all and allow list of hosts.
		:type allow_hosts: int

		:param hosts: User access rules: a textual list of hosts (host access).
		:type hosts: list of string

		:param allow_ifaces: User access rules: 0 allow all and deny list of ifaces (default), 1 deny all and allow list of ifaces.
		:type allow_ifaces: int

		:param ifaces: User access rules: a textual list of ifaces (interfaces access).
		:type ifaces: list of string

		"""

		request = """<modify_user user_id="%s">""" % user_id

		if new_name:
			request += """<new_name>%s</new_name>""" % new_name

		if password:
			request += """<password>%s</password>""" % password

		if role_id:
			request += """<role id="%s"/>""" % role_id

		###HOSTS###
		if not hosts:
			allow_hosts = '0'
		if allow_hosts:
			request += """<hosts allow="%s">""" % allow_hosts
		else:
			request += """<hosts>"""

		if hosts:
			request += """%s""" % str(",".join(hosts))
		request += """</hosts>"""

		###IFACES###
		if not hosts:
			allow_ifaces = '0'
		if allow_ifaces:
			request += """<ifaces allow="%s">""" % allow_ifaces
		else:
			request += """<ifaces>"""

		if ifaces:
			request += """%s""" % str(",".join(ifaces))
		request += """</ifaces>"""

		request += """</modify_user>"""

		self._manager.make_xml_request(request, xml_result=True)

	# ----------------------------------------------------------------------

	def get_users(self, user_id=None):
		"""
		Get a user in OpenVAS.

		:param user_id: ID of single user to get.
		:type user_id: str

		:return: The user.
		:rtype: str

		"""

		if not user_id:
			elems = self._manager.make_xml_request("""<get_users/>""", xml_result=True)
			m_return = {}

			for x in elems.findall("user"):
				m_return[x.find("name").text.lower()] = x.get("id")

			return m_return
		else:
			if not isinstance(user_id, str):
				raise TypeError("Expected string, got %r instead" % type(user_id))

			return self._manager.make_xml_request("""<get_users user_id='%s'/>""" % user_id, xml_result=True).find('.//user[@id="%s"]' % user_id)

	# ----------------------------------------------------------------------
	#
	# METHODS FOR PORT_LISTS
	#
	# ----------------------------------------------------------------------
	def create_port_list(self, name, port_range, comment=""):
		"""
		Creates a port list in OpenVAS.

		:param name: name to the port list
		:type name: str

		:param port_range: Port ranges. Should be a string of the form "T:22-80,U:53,88,1337"
		:type port_range: str

		:param comment: comment to add to the port list
		:type comment: str

		:return: the ID of the created target.
		:rtype: str

		:raises: ClientError, ServerError TODO
		"""
		request = """<create_port_list>
				<name>%s</name>
				<port_range>%s</port_range>
				<comment>%s</comment>
		</create_port_list>""" % (name, port_range, comment)

		return self._manager.make_xml_request(request, xml_result=True).get("id")

	# ----------------------------------------------------------------------

	def delete_port_list(self, port_list_id):
		"""
		Delete a user in OpenVAS.

		:param port_list_id: The ID of the port list to be deleted
		:type port_list_id: str

		:param name: The name of the user to be deleted.
		:type name: str

		"""

		request = """<delete_port_list port_list_id="%s"/>"""%port_list_id

		self._manager.make_xml_request(request, xml_result=True)

	# ----------------------------------------------------------------------

	def get_port_lists(self, port_list_id=None):
		"""
		Get a user in OpenVAS.

		:param port_list_id: ID of single port list to get.
		:type port_list_id: str

		:return: port list dict
		:rtype: str

		"""
		m_return = {}

		if not port_list_id:
			elems = self._manager.make_xml_request("""<get_port_lists details='1'/>""", xml_result=True)

			for x in elems.findall("port_list"):
				port_ranges = []
				for r in x.findall("port_ranges/port_range"):
					type = r.find('type').text
					start = r.find('start').text
					end = r.find('end').text
					port_ranges.append("%s:%s-%s" % (type, start, end))

				m_return[x.find("name").text.lower()] = {'id' : x.get("id"), 'port_ranges': port_ranges}
		else:
			if not isinstance(port_list_id, str):
				raise TypeError("Expected string, got %r instead" % type(port_list_id))

			port_list = self._manager.make_xml_request("""<get_port_lists port_list_id='%s' details='1'/>""" % port_list_id, xml_result=True).find('.//port_list[@id="%s"]' % port_list_id)
			port_ranges = []
			for r in port_list.findall("port_ranges/port_range"):
				type = r.find('type').text
				start = r.find('start').text
				end = r.find('end').text
				port_ranges.append("%s:%s-%s" % (type, start, end))

			m_return[port_list.find("name").text.lower()] = {'id' : port_list.get("id"), 'port_ranges': port_ranges}

		return m_return
	# ----------------------------------------------------------------------

	# ----------------------------------------------------------------------
	#
	# METHODS FOR OTHER
	#
	# ----------------------------------------------------------------------
	def create_schedule(self, name, hour, minute, month, day, year, period=None, duration=None,timezone="UTC"):
		"""
		Creates a schedule in the OpenVAS server.

		:param name: name to the schedule
		:type name: str

		:param hour: hour at which to start the schedule, 0 to 23
		:type hour: str

		:param minute: minute at which to start the schedule, 0 to 59
		:type minute: str

		:param month: month at which to start the schedule, 1-12
		:type month: str

		:param year: year at which to start the schedule
		:type year: str

		:param timezone: The timezone the schedule will follow. The format of a timezone is the same as that of the TZ environment variable on GNU/Linux systems
		:type timezone: str

		:param period:How often the Manager will repeat the scheduled task. Assumed unit of days
		:type period: str

		:param duration: How long the Manager will run the scheduled task for. Assumed unit of hours
		:type period: str

		:return: the ID of the created schedule.
		:rtype: str

		:raises: ClientError, ServerError
		"""
		request = """<create_schedule>
				<name>%s</name>
				<first_time>
				<hour>%s</hour>
				<minute>%s</minute>
				<month>%s</month>
				<day_of_month>%s</day_of_month>
				<year>%s</year>
				</first_time>
				<timezone>%s</timezone>
				<comment>%s</comment>""" % (name, hour, minute, month, day, year, timezone, "")
		if duration:
			request += """<duration>%s<unit>hour</unit></duration>""" % (duration)
		else:
			request += """<duration>0<unit>hour</unit></duration>"""
		if period:
			request += """<period>
				%s
				<unit>day</unit>
				</period>""" % (period)
		else:
			request += """<period>0<unit>day</unit></period>"""
		request += """
	</create_schedule>"""

		return self._manager.make_xml_request(request, xml_result=True).get("id")

	# ----------------------------------------------------------------------

	def get_schedules(self, schedule_id=None, tasks="1"):
		"""
		Get schedules in the server.

		If schedule_id is provided, only get the schedule associated to this id.

		:param schedule_id: schedule id to get
		:type schedule_id: str

		:return: `ElementTree`

		:raises: ClientError, ServerError
		"""
		if schedule_id:
			return self._manager.make_xml_request('<get_schedules schedule_id="%s" tasks="%s"/>' % (schedule_id, tasks), xml_result=True)
		else:
			return self._manager.make_xml_request('<get_schedules tasks="%s"/>' % tasks, xml_result=True)

	# ----------------------------------------------------------------------

	def get_tasks_schedules(self, schedule_id):
		"""
		Get tasks that have schedule in the server.

		:return: list of dicts [{'task_id':task_ID, 'schedule_id':schedule_ID}]

		:raises: ClientError, ServerError
		"""

		results = []

		schedules = self.get_schedules(schedule_id).findall('schedule')

		for s in schedules:
			schedule_id = s.get('id')
			tasks = s.findall('tasks/task')

			for task in tasks:
				results.append({'task_id':task.get('id'), 'schedule_id':schedule_id})

		return results
	# ----------------------------------------------------------------------

	def delete_schedule(self, schedule_id, ultimate=False):
		"""
		Delete a schedule.

		:param schedule_id: schedule_id
		:type schedule_id: str

		:param ultimate: remove or not from trashcan
		:type ultimate: bool

		:raises: AuditNotFoundError, ServerError
		"""

		request = """<delete_schedule schedule_id="%s" ultimate="%s" />""" % (schedule_id, int(ultimate))

		self._manager.make_xml_request(request, xml_result=True)

	# ----------------------------------------------------------------------
	# ----------------------------------------------------------------------
	#
	# METHODS FOR CONFIG
	#
	# ----------------------------------------------------------------------
	def get_configs(self, config_id=None):
		"""
		Get information about the configs in the server.

		If name param is provided, only get the config associated to this name.

		:param config_id: config id to get
		:type config_id: str

		:return: `ElementTree`

		:raises: ClientError, ServerError
		"""
		# Recover all config from OpenVAS
		if config_id:
			return self._manager.make_xml_request('<get_configs config_id="%s"/>' % config_id, xml_result=True)
		else:
			return self._manager.make_xml_request("<get_configs />", xml_result=True)

	# ----------------------------------------------------------------------
	def get_configs_ids(self, name=None):
		"""
		Get information about the configured profiles (configs)in the server.

		If name param is provided, only get the ID associated to this name.

		:param name: config name to get
		:type name: str

		:return: a dict with the format: {config_name: config_ID}

		:raises: ClientError, ServerError
		"""
		m_return = {}

		for x in self.get_configs().findall("config"):
			m_return[x.find("name").text] = x.get("id")

		if name:
			return {name: m_return[name]}
		else:
			return m_return

	# ----------------------------------------------------------------------
	#
	# METHODS FOR TARGET
	#
	# ----------------------------------------------------------------------

	def create_target(self, name, hosts, comment="", port_list=""):
		"""
		Creates a target in OpenVAS.

		:param name: name to the target
		:type name: str

		:param hosts: target list. Can be only one target or a list of targets
		:type hosts: str | list(str)

		:param comment: comment to add to task
		:type comment: str

		:param port_list: Port List ID to use for the target
		:type port_list: str

		:return: the ID of the created target.
		:rtype: str

		:raises: ClientError, ServerError
		"""

		if not port_list:
			port_list = self.get_port_lists().get("openvas default").get('id')

		from collections import Iterable
		if isinstance(hosts, str):
			m_targets = hosts
		elif isinstance(hosts, Iterable):
			m_targets = str(",".join(hosts))

		request = """<create_target>
				<name>%s</name>
				<hosts>%s</hosts>""" % (name, m_targets)

		if port_list:
			request += """<port_list id="%s"/>"""%port_list

		if comment:
			request += """<comment>%s</comment>"""%comment

		request += """</create_target>"""

		return self._manager.make_xml_request(request, xml_result=True).get("id")

	# ----------------------------------------------------------------------

	def delete_target(self, target_id):
		"""
		Delete a target in OpenVAS server.

		:param target_id: target id
		:type target_id: str

		:raises: ClientError, ServerError
		"""

		request = """<delete_target target_id="%s" />""" % target_id

		self._manager.make_xml_request(request, xml_result=True)

	# ----------------------------------------------------------------------

	def get_targets(self, target_id=None):
		"""
		Get information about the targets in the server.

		If name param is provided, only get the target associated to this name.

		:param target_id: target id to get
		:type target_id: str

		:return: `ElementTree` | None

		:raises: ClientError, ServerError
		"""
		m_return = {}
		# Recover all config from OpenVAS
		if target_id:
			targets = self._manager.make_xml_request('<get_targets id="%s"/>' % target_id,
												  xml_result=True).find('.//target[@id="%s"]' % target_id)
		else:
			targets = self._manager.make_xml_request("<get_targets />", xml_result=True)

		for x in targets.findall("target"):
			m_return[x.find("name").text] = x.get("id")

		return m_return

	# ----------------------------------------------------------------------

	def get_targets_ids(self, name=None):
		"""
		Get IDs of targets of the server.

		If name param is provided, only get the ID associated to this name.

		:param name: target name to get
		:type name: str

		:return: a dict with the format: {target_name: target_ID}

		:raises: ClientError, ServerError
		"""

		m_return = self.get_targets()

		if name:
			return m_return.get(name)
		else:
			return m_return

	# ----------------------------------------------------------------------
	#
	# METHODS FOR TASK
	#
	# ----------------------------------------------------------------------

	def create_task(self, name, target, config=None, schedule=None, comment="", max_checks=None, max_hosts=None):
		"""
		Creates a task in OpenVAS.

		:param name: name to the task
		:type name: str

		:param target: target to scan
		:type target: str

		:param config: config (profile) name
		:type config: str

		:param schedule: schedule ID to use.
		:type schedule: str

		:param comment: comment to add to task
		:type comment: str

		:param max_hosts: Maximum concurrently scanned hosts.
		:type max_hosts: int

		:param max_checks: Maximum concurrently executed NVTs per host.
		:type max_checks: int

		:return: the ID of the task created.
		:rtype: str

		:raises: ClientError, ServerError
		"""

		if not config:
			config = "Full and fast"

		request = """<create_task>
			<name>%s</name>
			<comment>%s</comment>
			<config id="%s"/>
			<target id="%s"/>""" % (name, comment, config, target)

		if schedule:
			request += """<schedule>%s</schedule>""" % (schedule)


		if max_checks or max_hosts:
			request += """<preferences>"""

			if max_checks:
				request += """<preference>
								<scanner_name>max_checks</scanner_name>
								<value>%s</value>
							</preference>""" % max_checks
			if max_hosts:
				request += """<preference>
								<scanner_name>max_hosts</scanner_name>
								<value>%s</value>
							</preference>""" % max_hosts

			request += """</preferences>"""

		request += """</create_task>"""

		return self._manager.make_xml_request(request, xml_result=True).get("id")

	# ----------------------------------------------------------------------

	def start_task(self, task_id):
		"""
		Start a task.

		:param task_id: ID of task to start.
		:type task_id: str

		:raises: ClientError, ServerError
		"""
		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		m_query = '<start_task task_id="%s"/>' % task_id

		m_response = self._manager.make_xml_request(m_query, xml_result=True)

		return m_response

	# ----------------------------------------------------------------------

	def delete_task(self, task_id, ultimate=False):
		"""
		Delete a task in OpenVAS server.

		:param task_id: task id
		:type task_id: str

		:param ultimate: remove or not from trashcan
		:type ultimate: bool

		:raises: AuditNotFoundError, ServerError
		"""
		request = """<delete_task task_id="%s" ultimate="%s" />""" % (task_id, int(ultimate))

		try:
			self._manager.make_xml_request(request, xml_result=True)
		except ClientError:
			raise AuditNotFoundError()

	# ----------------------------------------------------------------------

	def stop_task(self, task_id):
		"""
		Stops a task in OpenVAS server.

		:param task_id: task id
		:type task_id: str

		:raises: ServerError, AuditNotFoundError
		"""

		request = """<stop_task task_id="%s" />""" % task_id

		self._manager.make_xml_request(request, xml_result=True)

	# ----------------------------------------------------------------------

	def _get_tasks(self, task_id=None):
		"""
		Get information about the configured profiles in the server.

		If name param is provided, only get the task associated to this name.

		:param task_id: task id to get
		:type task_id: str

		:return: `ElementTree` | None

		:raises: ClientError, ServerError
		"""
		# Recover all task from OpenVAS

		if task_id:
			return self._manager.make_xml_request('<get_tasks id="%s"/>' % task_id,
												  xml_result=True).find('.//task[@id="%s"]' % task_id)
		else:
			return self._manager.make_xml_request("<get_tasks />", xml_result=True)


	def get_tasks(self, task_id=None):
		"""
		Get information about the configured profiles in the server.

		If name param is provided, only get the task associated to this name.

		:param task_id: task id to get
		:type task_id: str

		:return: `ElementTree` | None

		:raises: ClientError, ServerError
		"""
		# Recover all task from OpenVAS

		m_return = {}

		if task_id:
			tasks = self._get_tasks(task_id).find('.//task[@id="%s"]' % task_id)
		else:
			tasks = self._get_tasks()

		for x in tasks.findall("task"):
			m_return[x.find("name").text] = x.get("id")

		return m_return

	# ----------------------------------------------------------------------

	def get_tasks_ids(self, name=None):
		"""
		Get IDs of tasks of the server.

		If name param is provided, only get the ID associated to this name.

		:param name: task name to get
		:type name: str

		:return: a dict with the format: {task_name: task_ID}

		:raises: ClientError, ServerError
		"""
		m_return = self.get_tasks()

		if name:
			return m_return.get(name)
		else:
			return m_return

	# ----------------------------------------------------------------------

	def get_tasks_progress(self, task_id):
		"""
		Get the progress of the task.

		:param task_id: ID of the task
		:type task_id: str

		:return: a float number between 0-100
		:rtype: float

		:raises: ClientError, ServerError
		"""
		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		m_sum_progress = 0.0  # Partial progress
		m_progress_len = 0.0  # All of tasks

		# Get status with xpath
		tasks = self._get_tasks()
		status = tasks.find('.//task[@id="%s"]/status' % task_id)

		if status is None:
			raise ServerError("Task not found")

		if status.text in ("Running", "Pause Requested", "Paused"):
			h = tasks.findall('.//task[@id="%s"]/progress/host_progress/host' % task_id)

			if h is not None:
				m_progress_len += float(len(h))
				m_sum_progress += sum([float(x.tail) for x in h])

		elif status.text in ("Delete Requested", "Done", "Stop Requested", "Stopped", "Internal Error"):
			return 100.0  # Task finished

		try:
			return m_sum_progress / m_progress_len
		except ZeroDivisionError:
			return 0.0

	# ----------------------------------------------------------------------

	def get_tasks_detail(self, task_id):
		"""
		Get the xml of the details associated to the task ID.

		:param task_id: ID of task.
		:type task_id: str

		:return: xml object
		:rtype: `ElementTree`

		:raises: ClientError, ServerError
		"""

		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		try:
			m_response = self._manager.make_xml_request('<get_tasks task_id="%s" details="1"/>' % task_id,
														xml_result=True)
		except ServerError as e:
			raise VulnscanServerError("Can't get the detail for the task %s. Error: %s" % (task_id, e.message))

		return m_response

	# ----------------------------------------------------------------------

	def get_task_status(self, task_id):
		"""
		Get task status

		:param task_id: ID of task to check.
		:type task_id: str

		:return: status of a task
		:rtype: str

		:raises: ClientError, ServerError
		"""
		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		status = self._get_tasks().find('.//task[@id="%s"]/status' % task_id)

		if status is None:
			raise ServerError("Task not found")

		return status.text

	# ----------------------------------------------------------------------

	def is_task_running(self, task_id):
		"""
		Return true if task is running

		:param task_id: ID of task to check.
		:type task_id: str

		:return: bool
		:rtype: bool

		:raises: ClientError, ServerError
		"""

		if not isinstance(task_id, str):
			raise TypeError("Expected string, got %r instead" % type(task_id))

		status = self.get_task_status(task_id)

		if status is None:
			raise ServerError("Task not found")

		return status in ("Running", "Requested")

	# ----------------------------------------------------------------------

	def get_tasks_ids_by_status(self, status="Done"):
		"""
		Get IDs of tasks of the server depending of their status.

		Allowed status are: "Done", "Paused", "Running", "Stopped".

		If name param is provided, only get the ID associated to this name.

		:param status: get task with this status
		:type status: str - ("Done" |"Paused" | "Running" | "Stopped".)

		:return: a dict with the format: {task_name: task_ID}

		:raises: ClientError, ServerError
		"""
		if status not in ("Done", "Paused", "Running", "Stopped"):
			raise ValueError("Requested status are not allowed")

		m_task_ids = {}

		for x in self._get_tasks().findall("task"):
			if x.find("status").text == status:
				m_task_ids[x.find("name").text] = x.attrib["id"]

		return m_task_ids

	# ----------------------------------------------------------------------

	def get_results(self, task_id=None):
		"""
		Get the results associated to the scan ID.

		:param task_id: ID of scan to get. All if not provided
		:type task_id: str

		:return: xml object
		:rtype: `ElementTree`

		:raises: ClientError, ServerError
		"""

		if task_id:
			m_query = '<get_results task_id="%s"/>' % task_id
		else:
			m_query = '<get_results/>'

		return self._manager.make_xml_request(m_query, xml_result=True)

	# ----------------------------------------------------------------------
	#
	# METHODS FOR REPORT
	#
	# ----------------------------------------------------------------------

	def get_report_id(self, task_id):
		"""
		Get the report id associated to the task ID.

		:param task_id: ID of scan to get.
		:type task_id: str

		:return: ID of the report or None if the report isn't found
		:rtype: str

		"""
		m_response = self.get_tasks_detail(task_id)

		report = m_response.find('task').find('last_report')

		if not report:
			report = m_response.find('task').find("current_report")

		if report:
			return report[0].get("id")
		else:
			return

	# ----------------------------------------------------------------------

	def get_report_html(self, report_id):
		"""
		Get the html associated to the report ID.

		:param report_id: ID of report to get.
		:type report_id: str

		:return: base64 representing html page
		:rtype: base64

		"""
		if not isinstance(report_id, str):
			raise TypeError("Expected string, got %r instead" % type(report_id))

		m_response = ""

		try:
			m_response = self._manager.make_xml_request(
				'<get_reports report_id="%s" format_id="6c248850-1f62-11e1-b082-406186ea4fc5"/>' % report_id,
				xml_result=True)
		except ServerError as e:
			print("Can't get the HTML for the report %s. Error: %s" % (report_id, e.message))

		return m_response

	# ----------------------------------------------------------------------

	def get_report_xml(self, report_id):
		"""
		Get the xml associated to the report ID.

		:param report_id: ID of report to get.
		:type report_id: str

		:return: xml object
		:rtype: `ElementTree`

		"""
		if not isinstance(report_id, str):
			raise TypeError("Expected string, got %r instead" % type(report_id))

		try:
			m_response = self._manager.make_xml_request('<get_reports report_id="%s" />' % report_id, xml_result=True)
		except ServerError as e:
			print("Can't get the xml for the report %s. Error: %s" % (report_id, e.message))

		return m_response

	# ----------------------------------------------------------------------

	def delete_report(self, report_id):
		"""
		Delete a report in OpenVAS server.

		:param report_id: report id
		:type report_id: str

		:raises: AuditNotFoundError, ServerError
		"""
		request = """<delete_report report_id="%s" />""" % report_id

		try:
			self._manager.make_xml_request(request, xml_result=True)
		except ClientError:
			raise AuditNotFoundError()

	# ----------------------------------------------------------------------
	#
	# METHODS FOR SYNC
	#
	# ----------------------------------------------------------------------

	def sync_cert(self):
		"""
		Do the sync of cert.
		"""
		self._manager.make_xml_request('<sync_cert/>', xml_result=True)

	# ----------------------------------------------------------------------

	def sync_feed(self):
		"""
		Do the sync of feed.
		"""
		self._manager.make_xml_request('<sync_feed/>', xml_result=True)

	# ----------------------------------------------------------------------

	def sync_scap(self):
		"""
		Do the sync of scap.
		"""
		self._manager.make_xml_request('<sync_scap/>', xml_result=True)

	# ----------------------------------------------------------------------

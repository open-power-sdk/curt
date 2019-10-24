#!/usr/bin/python
# Copyright (c) IBM 2017 All Rights Reserved.
# Project name: curt
# This project is licensed under the GPL License 2.0, see LICENSE.

from __future__ import print_function
import os
import sys
import string
import argparse
import platform
import subprocess

if 'PERF_EXEC_PATH' in os.environ:
	sys.path.append(os.environ['PERF_EXEC_PATH'] + \
		'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
	description='''
Report system-wide utilization statistics

Process a perf format trace file containing some or all of the following event sets:
- raw_syscalls:sys_enter, raw_syscalls:sys_exit
- sched:sched_switch
- sched:sched_migrate_task
- sched:sched_process_fork, sched:sched_process_exec, sched:sched_process_exit
- sched:sched_stat_runtime, sched:sched_stat_blocked, sched:sched_stat_iowait, sched:sched_stat_wait, sched:sched_stat_sleep
- irq:irq_handler_entry, irq:irq_handler_exit
- powerpc:hcall_entry, powerpc:hcall_exit

Report the following statistics
- per-process, perf-task, per-CPU:
  - user, system, hypervisor, idle time
  - runtime, sleep, wait, blocked, iowait time
  - utilization
  - migrations
  - per-syscall, per-hcall:
    - count, elapse, pending, average, minimum, maximum
''',
	epilog='''
Record using perf (to perf.data file):
$ perf record -e '{raw_syscalls:sys_enter,raw_syscalls:sys_exit, ...}' command

Generate report (from perf.data file):
$ ./curt.py

Or, record and report in a single step:
$ ./curt.py --record all command
''')
parser.add_argument('--debug', action='store_true', help='enable debugging output')
parser.add_argument('--window', type=int, help='maximum event sequence length for correcting out-of-order events', default=20)
parser.add_argument('--record',
	metavar='EVENTLIST',
	help="record events (instead of generating report). "
		"Specify event group(s) as a comma-separated list from "
		"{all,sched,stats,syscalls,irqs,hcalls}.")
parser.add_argument('file_or_command',
	nargs=argparse.REMAINDER,
	help="the perf format data file to process (default: \"perf.data\"), or "
		"the command string to record (with \"--record\")",
	metavar='ARG',
	default='perf.data')
params = parser.parse_args()

if params.record:
	eventlist = ''
	comma = ''
	groups = params.record.split(',')
	if 'all' in groups or 'sched' in groups:
		eventlist = eventlist + comma + "sched:sched_switch," \
		"sched:sched_process_fork,sched:sched_process_exec," \
		"sched:sched_process_exit"
		comma = ','
	if 'all' in groups or 'syscalls' in groups:
		eventlist = eventlist + comma + \
			'raw_syscalls:sys_enter,raw_syscalls:sys_exit'
		comma = ','
	if 'all' in groups or 'irqs' in groups:
		eventlist = eventlist + comma + \
			'irq:irq_handler_entry,irq:irq_handler_exit'
		comma = ','
	if ('all' in groups or 'hcalls' in groups) \
		and platform.machine()[0:3] == 'ppc':

		eventlist = eventlist + comma + \
			'powerpc:hcall_entry,powerpc:hcall_exit'
		comma = ','
	if 'all' in groups or 'stats' in groups:
		eventlist = eventlist + comma + "sched:sched_stat_runtime," \
		"sched:sched_stat_blocked,sched:sched_stat_iowait," \
		"sched:sched_stat_wait,sched:sched_stat_sleep"
		comma = ','
	eventlist = '{' + eventlist + '}'
	command = ['perf', 'record', '--quiet', '--all-cpus',
		'--event', eventlist ] + params.file_or_command
	if params.debug:
		print(command)
	subprocess.call(command)
	params.file_or_command = []

try:
	from perf_trace_context import *
except:
	print("Relaunching under \"perf\" command...")
	if len(params.file_or_command) == 0:
		params.file_or_command = [ "perf.data" ]
	sys.argv = ['perf', 'script', '-i' ] + params.file_or_command + [ '-s', sys.argv[0] ]
	sys.argv.append('--')
	sys.argv += ['--window', str(params.window)]
	if params.debug:
		sys.argv.append('--debug')
	if params.debug:
		print(sys.argv)
	os.execvp("perf", sys.argv)
	sys.exit(1)

from Core import *
from Util import *

global start_timestamp, curr_timestamp

class CPU:
	def __init__(self):
		self.sys = 0
		self.user = 0
		self.idle = 0
		self.irq = 0
		self.hv = 0
		self.busy_unknown = 0
		self.runtime = 0
		self.sleep = 0
		self.wait = 0
		self.blocked = 0
		self.iowait = 0
		self.unaccounted = 0

	def accumulate(self, cpu):
		self.user += cpu.user
		self.sys += cpu.sys
		self.irq += cpu.irq
		self.hv += cpu.hv
		self.idle += cpu.idle
		self.busy_unknown += cpu.busy_unknown
		self.runtime += cpu.runtime
		self.sleep += cpu.sleep
		self.wait += cpu.wait
		self.blocked += cpu.blocked
		self.iowait += cpu.iowait
		self.unaccounted += cpu.unaccounted

	def output_header(self):
		print("%12s %12s %12s %12s %12s %12s | %12s %12s %12s %12s %12s %12s | %5s%%" % \
			("user", "sys", "irq", "hv", "busy", "idle", "runtime", "sleep", "wait", "blocked", "iowait", "unaccounted", "util"),end=' ')

	def output(self):
		print("%12.6f %12.6f %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f" % \
			(ns2ms(self.user), ns2ms(self.sys), ns2ms(self.irq), ns2ms(self.hv), ns2ms(self.busy_unknown), ns2ms(self.idle), \
			ns2ms(self.runtime), ns2ms(self.sleep), ns2ms(self.wait), ns2ms(self.blocked), ns2ms(self.blocked), ns2ms(self.unaccounted)),end=' ')
		running = self.user + self.sys + self.irq + self.hv + self.busy_unknown
		print("| %5.1f%%" % ((float(running * 100) / float(running + self.idle)) if running > 0 else 0),end=' ')

class Call:
	def __init__(self):
		self.timestamp = 0
		self.count = 0
		self.elapsed = 0
		self.min = sys.maxsize
		self.max = 0
		self.pending = 0
		self.call = 'unknown'
		self.calls = {}

	def accumulate(self, call):
		self.count += call.count
		self.elapsed += call.elapsed
		self.pending += call.pending
		if call.min < self.min:
			self.min = call.min
		if call.max > self.max:
			self.max = call.max

	def output_header(self):
		print("\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("ID", "name", "count", "elapsed", "pending", "average", "minimum", "maximum"),end=' ')

	def output(self, id, name):
		print("\t\t(%3s)%-20s %6u %12.6f %12.6f" % (id, name, self.count, ns2ms(self.elapsed), ns2ms(self.pending)),end=' ')
		if self.count > 0:
			print("%12.6f %12.6f %12.6f" % (ns2ms(float(self.elapsed)/float(self.count)), ns2ms(self.min), ns2ms(self.max)))
		else:
			print("%12s %12s %12s" % ("--", "--", "--"))

class Task:
	def __init__(self, timestamp, comm, mode, pid):
		self.timestamp = timestamp
		self.command = comm
		self.mode = mode
		self.resume_mode = 'busy-unknown'
		self.migrations = 0
		self.sched_stat = False
		self.pid = str(pid)
		self.cpu = 'unknown'
		self.cpus = {}
		self.syscall = 'unknown'
		self.syscall_timestamp = 0
		self.syscalls = {}
		self.irq = 'unknown'
		self.irq_timestamp = 0
		self.irqs = {}
		self.hcall = 'unknown'
		self.hcall_timestamp = 0
		self.hcalls = {}

	def change_mode(self, timestamp, mode):
		delta = timestamp - self.timestamp
		# TODO: there's probably a better way to do this
		if self.mode == 'user':
			self.cpus[self.cpu].user += delta
			debug_print("\t%s[%03u] = %u + %u = %u" % (self.mode, self.cpu, self.cpus[self.cpu].user - delta, delta, self.cpus[self.cpu].user))
		elif self.mode == 'sys':
			self.cpus[self.cpu].sys += delta
			debug_print("\t%s[%03u] = %u + %u = %u" % (self.mode, self.cpu, self.cpus[self.cpu].sys - delta, delta, self.cpus[self.cpu].sys))
		elif self.mode == 'idle':
			self.cpus[self.cpu].idle += delta
			debug_print("\t%s[%03u] = %u + %u = %u" % (self.mode, self.cpu, self.cpus[self.cpu].idle - delta, delta, self.cpus[self.cpu].idle))
		elif self.mode == 'irq':
			self.cpus[self.cpu].irq += delta
			debug_print("\t%s[%03u] = %u + %u = %u" % (self.mode, self.cpu, self.cpus[self.cpu].irq - delta, delta, self.cpus[self.cpu].irq))
		elif self.mode == 'hv':
			self.cpus[self.cpu].hv += delta
			debug_print("\t%s[%03u] = %u + %u = %u" % (self.mode, self.cpu, self.cpus[self.cpu].hv - delta, delta, self.cpus[self.cpu].hv))
		elif self.mode == 'busy-unknown':
			self.cpus[self.cpu].busy_unknown += delta
			debug_print("\t%s[%03u] = %u + %u = %u" % (self.mode, self.cpu, self.cpus[self.cpu].busy_unknown - delta, delta, self.cpus[self.cpu].busy_unknown))
		debug_print("\tnow %s" % (mode))
		self.mode = mode
		self.timestamp = timestamp

	def output_header(self):
		print("     -- [%8s] %-20s %3s" % ("task", "command", "cpu"),end=' ')
		for cpu in self.cpus:
			self.cpus[cpu].output_header()
			break # I just need one to emit the header
		print("%6s" % ("moves"),end=' ')

	def output_migrations(self):
		print("%6u" % (self.migrations),end=' ')

tasks = {}

def debug_print(s):
	if params.debug:
		print(s)

# convert string in the form of a bytearray with null termination
# (plus garbage thereafter)
# to a shorter bytearray without null termination
def null(ba):
	try:
		null = ba.find(b'\x00')
		if null >= 0:
			ba = ba[0:null]
		ba = ba.decode()
	except: pass
	return str(ba)

hcall_to_name = {
	'0x4':'H_REMOVE',
	'0x8':'H_ENTER',      
	'0xc':'H_READ',      
	'0x10':'H_CLEAR_MOD', 
	'0x14':'H_CLEAR_REF', 
	'0x18':'H_PROTECT', 
	'0x1c':'H_GET_TCE',
	'0x20':'H_PUT_TCE',
	'0x24':'H_SET_SPRG0',
	'0x28':'H_SET_DABR',
	'0x2c':'H_PAGE_INIT',
	'0x30':'H_SET_ASR',
	'0x34':'H_ASR_ON',
	'0x38':'H_ASR_OFF',
	'0x3c':'H_LOGICAL_CI_LOAD',
	'0x40':'H_LOGICAL_CI_STORE',
	'0x44':'H_LOGICAL_CACHE_LOAD',
	'0x48':'H_LOGICAL_CACHE_STORE',
	'0x4c':'H_LOGICAL_ICBI',
	'0x50':'H_LOGICAL_DCBF',
	'0x54':'H_GET_TERM_CHAR',
	'0x58':'H_PUT_TERM_CHAR',
	'0x5c':'H_REAL_TO_LOGICAL',
	'0x60':'H_HYPERVISOR_DATA',
	'0x64':'H_EOI',
	'0x68':'H_CPPR',
	'0x6c':'H_IPI',
	'0x70':'H_IPOLL',
	'0x74':'H_XIRR',
	'0x78':'H_MIGRATE_DMA',
	'0x7c':'H_PERFMON',
	'0xdc':'H_REGISTER_VPA',
	'0xe0':'H_CEDE',
	'0xe4':'H_CONFER',
	'0xe8':'H_PROD',
	'0xec':'H_GET_PPP',
	'0xf0':'H_SET_PPP',
	'0xf4':'H_PURR',
	'0xf8':'H_PIC',
	'0xfc':'H_REG_CRQ',
	'0x100':'H_FREE_CRQ',      
	'0x104':'H_VIO_SIGNAL',      
	'0x108':'H_SEND_CRQ',      
	'0x110':'H_COPY_RDMA',      
	'0x114':'H_REGISTER_LOGICAL_LAN',       
	'0x118':'H_FREE_LOGICAL_LAN',       
	'0x11c':'H_ADD_LOGICAL_LAN_BUFFER',
	'0x120':'H_SEND_LOGICAL_LAN',       
	'0x124':'H_BULK_REMOVE',      
	'0x130':'H_MULTICAST_CTRL',       
	'0x134':'H_SET_XDABR',      
	'0x138':'H_STUFF_TCE',      
	'0x13c':'H_PUT_TCE_INDIRECT',       
	'0x14c':'H_CHANGE_LOGICAL_LAN_MAC',
	'0x150':'H_VTERM_PARTNER_INFO',       
	'0x154':'H_REGISTER_VTERM',       
	'0x158':'H_FREE_VTERM',      
	'0x15c':'H_RESET_EVENTS',      
	'0x160':'H_ALLOC_RESOURCE',       
	'0x164':'H_FREE_RESOURCE',      
	'0x168':'H_MODIFY_QP',      
	'0x16c':'H_QUERY_QP',      
	'0x170':'H_REREGISTER_PMR',       
	'0x174':'H_REGISTER_SMR',      
	'0x178':'H_QUERY_MR',      
	'0x17c':'H_QUERY_MW',      
	'0x180':'H_QUERY_HCA',      
	'0x184':'H_QUERY_PORT',      
	'0x188':'H_MODIFY_PORT',      
	'0x18c':'H_DEFINE_AQP1',      
	'0x190':'H_GET_TRACE_BUFFER',       
	'0x194':'H_DEFINE_AQP0',      
	'0x198':'H_RESIZE_MR',      
	'0x19c':'H_ATTACH_MCQP',      
	'0x1a0':'H_DETACH_MCQP',      
	'0x1a4':'H_CREATE_RPT',      
	'0x1a8':'H_REMOVE_RPT',      
	'0x1ac':'H_REGISTER_RPAGES',       
	'0x1b0':'H_DISABLE_AND_GETC',       
	'0x1b4':'H_ERROR_DATA',      
	'0x1b8':'H_GET_HCA_INFO',      
	'0x1bc':'H_GET_PERF_COUNT',       
	'0x1c0':'H_MANAGE_TRACE',      
	'0x1d4':'H_FREE_LOGICAL_LAN_BUFFER',
	'0x1d8':'H_POLL_PENDING',      
	'0x1e4':'H_QUERY_INT_STATE',       
	'0x244':'H_ILLAN_ATTRIBUTES',       
	'0x250':'H_MODIFY_HEA_QP',      
	'0x254':'H_QUERY_HEA_QP',      
	'0x258':'H_QUERY_HEA',      
	'0x25c':'H_QUERY_HEA_PORT',       
	'0x260':'H_MODIFY_HEA_PORT',       
	'0x264':'H_REG_BCMC',      
	'0x268':'H_DEREG_BCMC',      
	'0x26c':'H_REGISTER_HEA_RPAGES',       
	'0x270':'H_DISABLE_AND_GET_HEA',       
	'0x274':'H_GET_HEA_INFO',      
	'0x278':'H_ALLOC_HEA_RESOURCE',       
	'0x284':'H_ADD_CONN',      
	'0x288':'H_DEL_CONN',      
	'0x298':'H_JOIN',      
	'0x2a4':'H_VASI_STATE',      
	'0x2b0':'H_ENABLE_CRQ',      
	'0x2b8':'H_GET_EM_PARMS',      
	'0x2d0':'H_SET_MPP',      
	'0x2d4':'H_GET_MPP',      
	'0x2ec':'H_HOME_NODE_ASSOCIATIVITY', 
	'0x2f4':'H_BEST_ENERGY',       
	'0x2fc':'H_XIRR_X',      
	'0x300':'H_RANDOM',      
	'0x304':'H_COP',      
	'0x314':'H_GET_MPP_X',      
	'0x31c':'H_SET_MODE',      
	'0xf000':'H_RTAS'
}

def hcall_name(opcode):
	try:
		return hcall_to_name[hex(opcode)]
	except:
		return str(opcode)

irq_to_name = {}

def irq_name(irq):
	if irq in irq_to_name:
		return irq_to_name[irq]
	return str(irq)

def trace_begin():
	pass

def trace_end():
	global events
	for event in events:
		event.process()

	# wrap up pending here
	for tid in tasks.keys():
		if tid == '0':
			continue

		task = tasks[tid]

		if task.mode == 'sys':
			syscall = task.syscalls[task.syscall]
			delta = curr_timestamp - syscall.timestamp
			cpu = task.cpus[task.cpu]
			syscall.pending += delta
			cpu.sys += delta
			cpu.runtime += delta
			debug_print("task %7s/%6s syscall %s pending time %f + %f = %fms" % (str(task.pid), tid, syscall_name(task.syscall), syscall.pending - delta, delta, syscall.pending))
			debug_print("task %7s/%6s (%s) sys time %f + %f = %fms" % (str(task.pid), tid, syscall_name(task.syscall), task.cpus[task.cpu].sys - delta, delta, task.cpus[task.cpu].sys))

		elif task.mode == 'irq':
			delta = curr_timestamp - task.irqs[task.irq].timestamp
			opcode = task.irq
			cpu = task.cpu
			task.irqs[opcode].pending += delta
			task.cpus[cpu].irq += delta
			task.cpus[cpu].runtime += delta
			debug_print("task %7s/%6s irq %s pending time %f + %f = %fms" % (str(task.pid), tid, irq_name(opcode), task.irqs[opcode].pending - delta, delta, task.irqs[opcode].pending))
			debug_print("task %7s/%6s (%s) irq time %f + %f = %fms" % (str(task.pid), tid, irq_name(opcode), task.cpus[cpu].irq - delta, delta, task.cpus[cpu].irq))

		elif task.mode == 'hv':
			delta = curr_timestamp - task.hcalls[task.hcall].timestamp
			opcode = task.hcall
			cpu = task.cpu
			task.hcalls[opcode].pending += delta
			task.cpus[cpu].hv += delta
			task.cpus[cpu].runtime += delta
			debug_print("task %7s/%6s hcall %s pending time %f + %f = %fms" % (str(task.pid), tid, hcall_name(opcode), task.hcalls[opcode].pending - delta, delta, task.hcalls[opcode].pending))
			debug_print("task %7s/%6s (%s) hcall time %f + %f = %fms" % (str(task.pid), tid, hcall_name(opcode), task.cpus[cpu].hv - delta, delta, task.cpus[cpu].hv))

		elif task.mode == 'user':
			delta = curr_timestamp - task.timestamp
			cpu = task.cpu
			task.cpus[cpu].user += delta
			task.cpus[cpu].runtime += delta
			debug_print("task %7s/%6s user time %f + %f = %fms" % (str(task.pid), tid, task.cpus[cpu].user - delta, delta, task.cpus[cpu].user))

		elif task.mode == 'idle':
			delta = curr_timestamp - task.timestamp
			cpu = task.cpu
			task.cpus[cpu].idle += delta
			task.cpus[cpu].unaccounted += delta
			debug_print("task %7s/%6s idle time %f + %f = %fms" % (str(task.pid), tid, task.cpus[cpu].idle - delta, delta, task.cpus[cpu].idle))
			# what if 'resume-mode' isn't set?
			# ...which is pretty likely if we're here and still 'busy-unknown'
			if task.resume_mode == 'sys':
				id = task.syscall
				cpu = task.cpu
				delta = curr_timestamp - task.syscalls[id].timestamp
				task.syscalls[id].pending += delta
				debug_print("task %7s/%6s syscall %s pending time %f + %f = %fms" % (str(task.pid), tid, syscall_name(id), task.syscalls[id].pending - delta, delta, task.syscalls[id].pending))

		elif task.mode == 'busy-unknown':
			delta = curr_timestamp - task.timestamp
			cpu = task.cpu
			task.cpus[cpu].busy_unknown += delta
			task.cpus[cpu].unaccounted += delta
			debug_print("task %7s/%6s busy-unknown %f + %f = %fms" % (str(task.pid), tid, task.cpus[cpu].busy_unknown - delta, delta, task.cpus[cpu].busy_unknown))

	print_task_stats(tasks)

start_timestamp = 0
curr_timestamp = 0

def ns2ms(nsecs):
	return nsecs * 0.000001

def getpid(perf_sample_dict):
	return perf_sample_dict['sample']['pid']

events = []
n_events = 0

def process_event(event):
	global events,n_events,curr_timestamp
	i = n_events
	while i > 0 and events[i-1].timestamp > event.timestamp:
		i = i-1
	events.insert(i,event)
	if n_events < params.window:
		n_events = n_events+1
	else:
		event = events[0]
		# need to delete from events list now,
		# because event.process() could reenter here
		del events[0]
		if event.timestamp < curr_timestamp:
			sys.stderr.write("Error: OUT OF ORDER events detected.\n  Try increasing the size of the look-ahead window with --window=<n>\n")
		event.process()
		if params.debug:
			print_task_stats({event.tid: tasks[str(event.tid)]})

class Event (object):

	def __init__(self):
		self.timestamp = 0
		self.cpu = 0
		self.tid = '0'
		self.command = 'unknown'
		self.mode = 'unknown'
		self.pid = 0

	def process(self):
		global start_timestamp

		try:
			task = tasks[self.tid]
			setpidmsg = ""
			if task.pid == 'unknown':
				tasks[self.tid].pid = self.pid
				setpidmsg = "\n\tset PID"
			debug_print("%016u %7s/%06u [%03u] %-32s%s" % (self.timestamp, str(tasks[self.tid].pid), self.tid, self.cpu, self.__class__.__name__, setpidmsg))
		except:
			debug_print("%016u %7s/%6s [%03u] %-32s\n\tnew Task" % (self.timestamp, str(self.pid), self.tid, self.cpu, self.__class__.__name__))
			task = Task(start_timestamp, self.command, self.mode, self.pid)
			tasks[str(self.tid)] = task

		if self.cpu not in task.cpus:
			debug_print("\tnew CPU")
			task.cpus[self.cpu] = CPU()
			if task.cpu == 'unknown':
				task.cpu = self.cpu

		if self.cpu != task.cpu:
			task.cpu = self.cpu
			task.migrations += 1

		return task

class Event_sys_enter ( Event ):

	def __init__(self, timestamp, cpu, tid, comm, id, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.id = id
		self.pid = pid
		self.mode = 'busy-unknown'
		
	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_sys_enter, self).process()

		if task.mode == 'sys':
			print("re-entered! syscall from signal handler??")
			sys.exit(0)

		if task.mode == 'busy-unknown':
			task.mode = 'user'
			for cpu in task.cpus:
				task.cpus[cpu].user = task.cpus[cpu].busy_unknown
				task.cpus[cpu].busy_unknown = 0

		task.syscall = self.id
		if self.id not in task.syscalls:
			task.syscalls[self.id] = Call()

		task.syscalls[self.id].timestamp = curr_timestamp
		task.change_mode(curr_timestamp, 'sys')

def raw_syscalls__sys_enter(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, id, args, perf_sample_dict):

	event = Event_sys_enter(nsecs(common_secs,common_nsecs), common_cpu, common_pid, common_comm, id, getpid(perf_sample_dict))
	process_event(event)

class Event_sys_exit ( Event ):

	def __init__(self, timestamp, cpu, tid, comm, id, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.id = id
		self.pid = pid
		self.mode = 'busy-unknown'
		
	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_sys_exit, self).process()

		pending = False

		if task.mode == 'busy-unknown':
			task.mode = 'sys'
			for cpu in task.cpus:
				task.cpus[cpu].sys = task.cpus[cpu].busy_unknown
				task.cpus[cpu].busy_unknown = 0
			pending = True

		if self.id == 'unknown':
			self.id = task.syscall
			print("%016u %7s/%06u [%03u] %-32s %-20s seccomp rejected syscall" % (self.timestamp, str(self.pid), self.tid, self.cpu, self.__class__.__name__, syscall_name(self.id)))

		elif self.id == 0 and syscall_name(self.id) == None:
			self.id = task.syscall
			print("%016u %7s/%06u [%03u] %-32s %-20s remapping syscall(0)" % (self.timestamp, str(self.pid), self.tid, self.cpu, self.__class__.__name__, syscall_name(self.id)))

		if self.id not in task.syscalls:
			task.syscalls[self.id] = Call()
			task.syscalls[self.id].timestamp = start_timestamp

		if task.mode != 'sys' and task.mode != 'idle':
			print("%016u %7s/%06u [%03u] %-32s %-20s spurious exit; mode was %s" % (self.timestamp, str(self.pid), self.tid, self.cpu, self.__class__.__name__, syscall_name(self.id), task.mode))
			# spurious exit: minimize impact to the data
			task.syscalls[self.id].timestamp = curr_timestamp

		if pending:
			delta = curr_timestamp - start_timestamp
			task.syscalls[self.id].pending = delta
			debug_print("\tsyscall %s pending time %uns" % (syscall_name(self.id), task.syscalls[self.id].pending))
		else:
			delta = curr_timestamp - task.syscalls[self.id].timestamp
			task.syscalls[self.id].count += 1
			task.syscalls[self.id].elapsed += delta 
			debug_print("\tdelta = %u min = %u max = %u" % (delta, task.syscalls[self.id].min, task.syscalls[self.id].max))
			if delta < task.syscalls[self.id].min:
				debug_print("\t%s min %u" % (syscall_name(self.id), delta))
				task.syscalls[self.id].min = delta
			if delta > task.syscalls[self.id].max:
				debug_print("\t%s max %u" % (syscall_name(self.id), delta))
				task.syscalls[self.id].max = delta
			debug_print("\tsyscall %s count %u time %uns elapsed %uns" % (syscall_name(self.id), task.syscalls[self.id].count, delta, task.syscalls[self.id].elapsed))

		if task.cpu != self.cpu:
			debug_print("migration within syscall!")
			task.migrations += 1
			delta /= 2
			debug_print("\tmigrations %u sys %u + %u = %u" % (task.syscalls[self.id].migrations, task.cpus[task.cpu].sys - delta, delta, task.cpus[task.cpu].sys))
			task.cpus[task.cpu].sys += delta
			task.syscalls[self.id].timestamp += delta

		task.change_mode(curr_timestamp, 'user')

def raw_syscalls__sys_exit(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, id, ret, perf_sample_dict):

	event = Event_sys_exit(nsecs(common_secs,common_nsecs), common_cpu, common_pid, common_comm, id, getpid(perf_sample_dict))
	process_event(event)

class Event_hcall_entry ( Event ):

	def __init__(self, timestamp, cpu, tid, comm, opcode, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.opcode = opcode
		self.pid = pid
		self.mode = 'busy-unknown'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_hcall_entry, self).process()

		task.resume_mode = task.mode
		task.hcall = self.opcode
		if self.opcode not in task.hcalls:
			task.hcalls[self.opcode] = Call()

		task.hcalls[self.opcode].timestamp = curr_timestamp
		task.change_mode(curr_timestamp, 'hv')

def powerpc__hcall_entry(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, opcode, perf_sample_dict):

	event = Event_hcall_entry(nsecs(common_secs,common_nsecs), common_cpu, common_pid, common_comm, opcode, getpid(perf_sample_dict))
	process_event(event)

class Event_hcall_exit ( Event ):

	def __init__(self, timestamp, cpu, tid, comm, opcode, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.opcode = opcode
		self.pid = pid
		self.mode = 'busy-unknown'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_hcall_exit, self).process()

		pending = False

		if task.mode == 'busy-unknown':
			task.mode = 'hv'
			for cpu in task.cpus:
				task.cpus[cpu].hv = task.cpus[cpu].busy_unknown
				task.cpus[cpu].busy_unknown = 0
			pending = True

		if self.opcode not in task.hcalls:
			task.hcalls[self.opcode] = Call()
			task.hcalls[self.opcode].timestamp = start_timestamp

		if pending:
			delta = curr_timestamp - start_timestamp
			task.hcalls[self.opcode].pending = delta
			debug_print("\thcall %s pending time %uns" % (hcall_name(self.opcode), task.hcalls[self.opcode].pending))
		else:
			delta = curr_timestamp - task.hcalls[self.opcode].timestamp
			task.hcalls[self.opcode].count += 1
			task.hcalls[self.opcode].elapsed += delta 
			debug_print("\tdelta = %u min = %u max = %u" % (delta, task.hcalls[self.opcode].min, task.hcalls[self.opcode].max))
			if delta < task.hcalls[self.opcode].min:
				debug_print("\t%s min %u" % (hcall_name(self.opcode), delta))
				task.hcalls[self.opcode].min = delta
			if delta > task.hcalls[self.opcode].max:
				debug_print("\t%s max %u" % (hcall_name(self.opcode), delta))
				task.hcalls[self.opcode].max = delta
			debug_print("\thcall %s count %u time %uns elapsed %uns" % (hcall_name(self.opcode), task.hcalls[self.opcode].count, delta, task.hcalls[self.opcode].elapsed))

		if task.cpu != self.cpu:
			debug_print("migration within hcall!")
			task.migrations += 1
			delta /= 2
			debug_print("\tmigrations %u hv %u + %u = %u" % (task.hcalls[self.opcode].migrations, task.cpus[task.cpu].hv - delta, delta, task.cpus[task.cpu].hv))
			task.cpus[task.cpu].hv += delta
			task.hcalls[self.opcode].timestamp += delta

		task.change_mode(curr_timestamp, task.resume_mode)

def powerpc__hcall_exit(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, opcode, retval, perf_sample_dict):

	event = Event_hcall_exit(nsecs(common_secs,common_nsecs), common_cpu, common_pid, common_comm, opcode, getpid(perf_sample_dict))
	process_event(event)

class Event_irq_handler_entry ( Event ):

	def __init__(self, timestamp, cpu, tid, comm, irq, name, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.irq = irq
		self.name = name
		self.pid = pid
		self.mode = 'busy-unknown'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_irq_handler_entry, self).process()

		task.resume_mode = task.mode
		task.irq = self.irq
		if self.irq not in task.irqs:
			task.irqs[self.irq] = Call()

		task.irqs[self.irq].timestamp = curr_timestamp
		task.change_mode(curr_timestamp, 'irq')

def irq__irq_handler_entry(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, irq, name, perf_sample_dict):

	irq_to_name[irq] = name
	event = Event_irq_handler_entry(nsecs(common_secs,common_nsecs), common_cpu, common_pid, common_comm, irq, name, getpid(perf_sample_dict))
	process_event(event)

class Event_irq_handler_exit ( Event ):

	def __init__(self, timestamp, cpu, tid, comm, irq, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.irq = irq
		self.pid = pid
		self.mode = 'busy-unknown'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_irq_handler_exit, self).process()

		pending = False

		if task.mode == 'busy-unknown':
			task.mode = 'irq'
			for cpu in task.cpus:
				task.cpus[cpu].irq = task.cpus[cpu].busy_unknown
				task.cpus[cpu].busy_unknown = 0
			pending = True

		if self.irq not in task.irqs:
			task.irqs[self.irq] = Call()
			task.irqs[self.irq].timestamp = start_timestamp

		if pending:
			delta = curr_timestamp - start_timestamp
			task.irqs[self.irq].pending = delta
			debug_print("\tirq %s pending time %uns" % (irq_name(self.irq), task.irqs[self.irq].pending))
		else:
			delta = curr_timestamp - task.irqs[self.irq].timestamp
			task.irqs[self.irq].count += 1
			task.irqs[self.irq].elapsed += delta 
			debug_print("\tdelta = %u min = %u max = %u" % (delta, task.irqs[self.irq].min, task.irqs[self.irq].max))
			if delta < task.irqs[self.irq].min:
				debug_print("\t%s min %u" % (irq_name(self.irq), delta))
				task.irqs[self.irq].min = delta
			if delta > task.irqs[self.irq].max:
				debug_print("\t%s max %u" % (irq_name(self.irq), delta))
				task.irqs[self.irq].max = delta
			debug_print("\tirq %s count %u time %uns elapsed %uns" % (irq_name(self.irq), task.irqs[self.irq].count, delta, task.irqs[self.irq].elapsed))

		if task.cpu != self.cpu:
			debug_print("migration within irq!")
			task.migrations += 1
			delta /= 2
			debug_print("\tmigrations %u irq %u + %u = %u" % (task.irqs[self.irq].migrations, task.cpus[task.cpu].irq - delta, delta, task.cpus[task.cpu].irq))
			task.cpus[task.cpu].irq += delta
			task.irqs[self.irq].timestamp += delta

		task.change_mode(curr_timestamp, task.resume_mode)

def irq__irq_handler_exit(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, irq, ret, perf_sample_dict):

	event = Event_irq_handler_exit(nsecs(common_secs,common_nsecs), common_cpu, common_pid, common_comm, irq, getpid(perf_sample_dict))
	process_event(event)

class Event_sched_switch_out (Event):

	def __init__(self, timestamp, cpu, tid, comm, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.pid = pid
		self.mode = 'busy-unknown'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_sched_switch_out, self).process()

		if task.sched_stat == False:
			task.sched_stat = True
			task.cpus[self.cpu].runtime = curr_timestamp - start_timestamp
			debug_print("\truntime = %u" % (task.cpus[self.cpu].runtime))

		task.resume_mode = task.mode
		task.change_mode(curr_timestamp, 'idle')

class Event_sched_switch_in (Event):

	def __init__(self, timestamp, cpu, tid, comm, pid ):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.pid = pid
		self.mode = 'idle'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_sched_switch_in, self).process()

		if task.sched_stat == False:
			task.sched_stat = True
			task.cpus[self.cpu].unaccounted = curr_timestamp - start_timestamp
			debug_print("\tunaccounted = %u" % (task.cpus[self.cpu].unaccounted))

		task.cpu = self.cpu

		task.change_mode(curr_timestamp, task.resume_mode)

def sched__sched_switch(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
	next_comm, next_pid, next_prio, perf_sample_dict):

	timestamp = nsecs(common_secs, common_nsecs)
	event = Event_sched_switch_out(timestamp, common_cpu, prev_pid, prev_comm, 'unknown')
	process_event(event)
	event = Event_sched_switch_in(timestamp, common_cpu, next_pid, next_comm, 'unknown')
	process_event(event)

class Event_sched_migrate_task (Event):

	def __init__(self, timestamp, cpu, tid, comm, dest_cpu, pid ):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.dest_cpu = dest_cpu
		self.pid = pid
		self.mode = 'idle'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		if self.cpu == self.dest_cpu:
			return

		task = super(Event_sched_migrate_task, self).process()

		task.migrations += 1

		task.change_mode(curr_timestamp, task.mode)
		if self.dest_cpu not in task.cpus:
			task.cpus[self.dest_cpu] = CPU()
		task.cpu = self.dest_cpu

def sched__sched_migrate_task(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, orig_cpu, 
	dest_cpu, perf_sample_dict):

	event = Event_sched_migrate_task(nsecs(common_secs,common_nsecs), orig_cpu, pid, comm, dest_cpu, 'unknown')
	process_event(event)

class Event_sched_process_exec (Event):

	def __init__(self, timestamp, cpu, tid, comm, filename, pid ):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = str(tid)
		self.command = comm
		self.filename = filename
		self.pid = pid
		self.mode = 'sys'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_sched_process_exec, self).process()

		new_task = Task(self.timestamp, self.command, task.mode, self.pid)
		new_task.sched_stat = True
		new_task.syscall = task.syscall
		new_task.syscalls[task.syscall] = Call()
		new_task.syscalls[task.syscall].timestamp = self.timestamp
		new_task.cpu = self.cpu
		new_task.cpus[self.cpu] = CPU()

		# close out current task stats and stow them somewhere,
		# because we're reusing the TID for a new process image,
		# for which we need to start new task stats

		task.change_mode(curr_timestamp, 'exit')

		suffix=0
		while True:
			old_tid = str(self.tid)+"-"+str(suffix)
			if old_tid in tasks:
				suffix += 1
			else:
				break
		debug_print("\t\"old\" task \"%s\"" % (old_tid))

		tasks[old_tid] = tasks[self.tid]
		if params.debug:
			print_task_stats({old_tid: tasks[old_tid]})

		del tasks[self.tid]

		tasks[self.tid] = new_task

def sched__sched_process_exec(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, filename, pid, old_pid, perf_sample_dict):

	event = Event_sched_process_exec(nsecs(common_secs,common_nsecs), common_cpu, common_pid, common_comm, filename, getpid(perf_sample_dict))
	process_event(event)

class Event_sched_process_fork (Event):

	def __init__(self, timestamp, cpu, tid, comm, parent_tid, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.pid = pid
		self.mode = 'idle'
		self.parent_tid = str(parent_tid)

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_sched_process_fork, self).process()
		task.timestamp = self.timestamp

		try:
			parent = tasks[self.parent_tid]
		except:
			# need to create parent task here!
			parent = Task(start_timestamp, self.command, 'sys', self.pid)
			parent.sched_stat = True # ?
			parent.cpu = self.cpu
			parent.cpus[parent.cpu] = CPU()
			tasks[self.parent_tid] = parent

		task.resume_mode = parent.mode # ? 'sys' ?
		task.sched_stat = True # ?
		task.syscall = parent.syscall
		task.syscalls[task.syscall] = Call()
		task.syscalls[task.syscall].timestamp = self.timestamp

def sched__sched_process_fork(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, parent_comm, parent_pid, child_comm, child_pid, perf_sample_dict):

	event = Event_sched_process_fork(nsecs(common_secs,common_nsecs), common_cpu, child_pid, child_comm, parent_pid, 'unknown')
	process_event(event)

class Event_sched_process_exit (Event):

	def __init__(self, timestamp, cpu, tid, comm, pid):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = tid
		self.command = comm
		self.pid = pid
		self.mode = 'sys'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		task = super(Event_sched_process_exit, self).process()

		task.change_mode(self.timestamp, 'exit')

def sched__sched_process_exit(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, perf_sample_dict):

	event = Event_sched_process_exit(nsecs(common_secs,common_nsecs), common_cpu, pid, comm, getpid(perf_sample_dict))
	process_event(event)

class Event_sched_stat (Event):

	def __init__(self, timestamp, cpu, tid, comm, delta, bucket):
		self.timestamp = timestamp
		self.cpu = cpu
		self.tid = str(tid)
		self.command = comm
		self.delta = delta
		self.bucket = bucket
		self.mode = 'busy-unknown'
		self.pid = 'unknown'

	def process(self):
		global start_timestamp, curr_timestamp
		curr_timestamp = self.timestamp
		if (start_timestamp == 0):
			start_timestamp = curr_timestamp

		# sched_stat events can occur on any cpu
		# so make sure this doesn't look like a migration
		try:
			task = tasks[self.tid]
			self.cpu = task.cpu
		except:
			pass

		task = super(Event_sched_stat, self).process()

		if task.sched_stat == False:
			task.sched_stat = True
			if self.delta > self.timestamp - start_timestamp:
				self.delta = self.timestamp - start_timestamp
			else:
				task.cpus[task.cpu].unaccounted = self.timestamp - start_timestamp - self.delta
				debug_print("\tunaccounted = %u" % (task.cpus[task.cpu].unaccounted))

		# TODO: there's probably a better way to do this
		if self.bucket == 'runtime':
			debug_print("\t%s %u + %u = %u" % (self.bucket, task.cpus[task.cpu].runtime, self.delta, task.cpus[task.cpu].runtime + self.delta))
			task.cpus[task.cpu].runtime += self.delta
		elif self.bucket == 'sleep':
			debug_print("\t%s %u + %u = %u" % (self.bucket, task.cpus[task.cpu].sleep, self.delta, task.cpus[task.cpu].sleep + self.delta))
			task.cpus[task.cpu].sleep += self.delta
		elif self.bucket == 'wait':
			debug_print("\t%s %u + %u = %u" % (self.bucket, task.cpus[task.cpu].wait, self.delta, task.cpus[task.cpu].wait + self.delta))
			task.cpus[task.cpu].wait += self.delta
		elif self.bucket == 'blocked':
			debug_print("\t%s %u + %u = %u" % (self.bucket, task.cpus[task.cpu].blocked, self.delta, task.cpus[task.cpu].blocked + self.delta))
			task.cpus[task.cpu].blocked += self.delta
		elif self.bucket == 'iowait':
			debug_print("\t%s %u + %u = %u" % (self.bucket, task.cpus[task.cpu].iowait, self.delta, task.cpus[task.cpu].iowait + self.delta))
			task.cpus[task.cpu].iowait += self.delta

def sched__sched_stat_runtime(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, runtime, vruntime, 
		perf_sample_dict):

	event = Event_sched_stat(nsecs(common_secs,common_nsecs), common_cpu, pid, comm, runtime, 'runtime')
	process_event(event)

def sched__sched_stat_blocked(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):

	event = Event_sched_stat(nsecs(common_secs,common_nsecs), common_cpu, pid, comm, delay, 'blocked')
	process_event(event)

def sched__sched_stat_iowait(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):

	event = Event_sched_stat(nsecs(common_secs,common_nsecs), common_cpu, pid, comm, delay, 'iowait')
	process_event(event)

def sched__sched_stat_wait(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):

	event = Event_sched_stat(nsecs(common_secs,common_nsecs), common_cpu, pid, comm, delay, 'wait')
	process_event(event)

def sched__sched_stat_sleep(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):

	event = Event_sched_stat(nsecs(common_secs,common_nsecs), common_cpu, pid, comm, delay, 'sleep')
	process_event(event)

#def trace_unhandled(event_name, context, event_fields_dict):
#	pass


def print_task_CPU(cpuinfo):
	print("%12.6f %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f" % (ns2ms(cpuinfo.user), ns2ms(cpuinfo.sys), ns2ms(cpuinfo.hv), ns2ms(cpuinfo.busy_unknown), ns2ms(cpuinfo.idle), ns2ms(cpuinfo.runtime), ns2ms(cpuinfo.sleep), ns2ms(cpuinfo.wait), ns2ms(cpuinfo.blocked), ns2ms(cpuinfo.blocked), ns2ms(cpuinfo.unaccounted)),end=' ')
	running = cpuinfo.user + cpuinfo.sys + cpuinfo.hv + cpuinfo.busy_unknown
	print("| %5.1f%%" % ((float(running * 100) / float(running + cpuinfo.idle)) if running > 0 else 0),end=' ')

def report_calls(calls, id2name, process_calls, system_calls):
	for id in calls:
		calls[id].output_header()
		print
		break # I just need one to emit the header
	for id in sorted(calls, key= lambda x: (calls[x].count, calls[x].elapsed), reverse=True):
		if id not in process_calls:
			process_calls[id] = Call()
		process_calls[id].accumulate(calls[id])
		if id not in system_calls:
			system_calls[id] = Call()
		system_calls[id].accumulate(calls[id])

		calls[id].output(id, id2name(id))

def print_task_stats(tasks):
	pids = []
	for tid in tasks:
		if tid == '0':
			continue
		pid = tasks[tid].pid
		if pid not in pids:	
			 pids.append(pid)
	if not pids:
		return
	print("--  PID:")
	system = Task(0, 'ALL', 'all', 'ALL')
	system_cpus_sum = CPU()
	process = Task(0, 'PROCESS', 'all', pid)
	process_cpus_sum = CPU()
	task_cpus_sum = CPU()
	for pid in sorted(pids):
		if pid == 0:
			continue
		print("%7s:" % (str(pid)))
		process.__init__(0, 'PROCESS', 'all', pid)
		process_cpus_sum.__init__()
		for tid in sorted(tasks):
			if tid == 0:
				continue
			task = tasks[tid]
			if task.pid == pid and task != 0:
				task.output_header()
				print()
				# each "comm" is delivered as a bytearray:
				#   the actual command, a null terminator, and garbage
				# "print" wants to splat every byte, including the garbage
				# so, truncate the bytearray at the null
				comm = null(task.command)
				task_cpus_sum.__init__()
				for cpu in task.cpus:
					print("\t[%8s] %-20s %3u" % (tid, comm, cpu),end=' ')
					task.cpus[cpu].output()
					print()
					task_cpus_sum.accumulate(task.cpus[cpu])
					if cpu not in process.cpus:
						process.cpus[cpu] = CPU()
					process.cpus[cpu].accumulate(task.cpus[cpu])
				process_cpus_sum.accumulate(task_cpus_sum)
				print("\t[%8s] %-20s ALL" % (tid, comm),end=' ')
				task_cpus_sum.output()
				task.output_migrations()
				print()
				process.migrations += task.migrations
				print()
				if task.syscalls:
					report_calls(task.syscalls, syscall_name, process.syscalls, system.syscalls)
					print()
				if task.hcalls:
					report_calls(task.hcalls, hcall_name, process.hcalls, system.hcalls)
					print()
				if task.irqs:
					report_calls(task.irqs, irq_name, process.irqs, system.irqs)
					print()

		process.output_header()
		print()
		print("\t[     ALL] %-20s ALL" % (""),end=' ')
		process_cpus_sum.output()
		process.output_migrations()
		print()
		print()

		for cpu in process.cpus:
			if cpu not in system.cpus:
				system.cpus[cpu] = CPU()
			system.cpus[cpu].accumulate(process.cpus[cpu])
		system_cpus_sum.accumulate(process_cpus_sum)
		system.migrations += process.migrations

	print("%7s:" % ("ALL"))
	for tid in tasks:
		tasks[tid].output_header()
		print()
		break # I just need one to emit the header
	print("\t[     ALL] %-20s ALL" % (""),end=' ')
	system_cpus_sum.output()
	system.output_migrations()
	print()
	print()
	if system.syscalls:
		for id in system.syscalls:
			system.syscalls[id].output_header()
			print()
			break # I just need one to emit the header
		for id in sorted(system.syscalls, key= lambda x: (system.syscalls[x].count, system.syscalls[x].elapsed), reverse=True):
			system.syscalls[id].output(id, syscall_name(id))
		print()

	if system.hcalls:
		for id in system.hcalls:
			system.hcalls[id].output_header()
			print()
			break # I just need one to emit the header
		for id in sorted(system.hcalls, key= lambda x: (system.hcalls[x].count, system.hcalls[x].elapsed), reverse=True):
			system.hcalls[id].output(id, hcall_name(id))
		print()

	if system.irqs:
		for id in system.irqs:
			system.irqs[id].output_header()
			print()
			break # I just need one to emit the header
		for id in sorted(system.irqs, key= lambda x: (system.irqs[x].count, system.irqs[x].elapsed), reverse=True):
			system.irqs[id].output(id, irq_name(id))
		print()

	print("Total Trace Time: %f ms" % ns2ms(curr_timestamp - start_timestamp))

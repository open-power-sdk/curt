#!/usr/bin/python
# Copyright (c) IBM 2017 All Rights Reserved.
# Project name: curt
# This project is licensed under the GPL License 2.0, see LICENSE.

import os
import sys
import string
import argparse

if 'PERF_EXEC_PATH' in os.environ:
	sys.path.append(os.environ['PERF_EXEC_PATH'] + \
		'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

usage = "perf script -s ./curt.py";

try:
	from perf_trace_context import *
except:
	print "This script must be run under perf:"
	print "\t" + usage
	sys.exit(1)

from Core import *
from Util import *

parser = argparse.ArgumentParser()
parser.add_argument('--debug', action='store_true', help='enable debugging output')
params = parser.parse_args()

global endTimestamp
global beginTimestamp

syscalls = autodict()
task_state = autodict()
task_info = autodict()

def debug_print(s):
	if params.debug:
		print s

# convert string in the form of a bytearray with null termination
# (plus garbage thereafter)
# to a shorter bytearray without null termination
def null(ba):
	null = ba.find('\x00')
	if null >= 0:
		ba = ba[0:null]
	return ba
	
def trace_begin():
	pass

def trace_end():
	# wrap up pending here
	for task in task_info.keys():
		if task == 0:
			continue

		if task_state[task]['mode'] == 'sys':
			delta = endTimestamp - task_state[common_tid]['sys_enter']
			id = task_state[common_tid]['id']
			cpu = task_state[task]['cpu']
			task_state[task]['pending'][id] += delta
			task_state[task]['sys'][cpu] += delta
			debug_print("task %u syscall %s pending time %f + %f = %fms" % (task, syscall_name(id), task_state[task]['pending'][id] - delta, delta, task_state[task]['pending'][id]))
			debug_print("task %u sys time %f + %f = %fms" % (task, syscall_name(id), task_state[task]['sys'][cpu] - delta, delta, task_state[task]['sys'][cpu]))

		elif task_state[task]['mode'] == 'user':
			delta = endTimestamp - task_state[task]['timestamp']
			cpu = task_state[task]['cpu']
			task_state[task]['user'][cpu] += delta
			debug_print("task %u user time %f + %f = %fms" % (task, task_state[task]['user'][cpu] - delta, delta, task_state[task]['user'][cpu]))

		elif task_state[task]['mode'] == 'idle':
			delta = endTimestamp - task_state[task]['timestamp']
			cpu = task_state[task]['cpu']
			task_state[task]['idle'][cpu] += delta
			debug_print("task %u idle time %f + %f = %fms" % (task, task_state[task]['idle'][cpu] - delta, delta, task_state[task]['idle'][cpu]))
			# what if 'resume-mode' isn't set?
			# ...which is pretty likely if we're here and still 'busy-unknown'
			if task_state[task]['resume-mode'] == 'sys':
				delta = endTimestamp - task_state[task]['sys_enter']
				id = task_state[task]['id']
				cpu = task_state[task]['cpu']
				task_state[task]['pending'][id] += delta
				debug_print("task %u syscall %s pending time %f + %f = %fms" % (task, syscall_name(id), task_state[task]['pending'][id] - delta, delta, task_state[task]['pending'][id]))

		elif task_state[task]['mode'] == 'busy-unknown':
			delta = endTimestamp - task_state[task]['timestamp']
			cpu = task_state[task]['cpu']
			task_state[task]['busy-unknown'][cpu] += delta
			debug_print("task %u busy-unknown %f + %f = %fms" % (task, task_state[task]['busy-unknown'][cpu] - delta, delta, task_state[task]['busy-unknown'][cpu]))

	print_syscall_totals(task_info.keys())

beginTimestamp = 0
endTimestamp = 0
cpu_processing_time = 0
def msecs(secs,nsecs):
	return ((secs * 1000000000) + nsecs)*0.000001

def new_task(tid, pid, comm):
	if tid != 0:
		debug_print("new task %u (%u:%s)" % (tid, pid, null(comm)))
	task_info[tid]['pid'] = pid
	task_info[tid]['comm'] = comm
	task_state[tid]['migrations'] = 0

def new_tid_cpu(tid, cpu):
	if tid != 0:
		debug_print("new CPU %d for task %u" % (cpu, tid))
	task_state[tid]['cpu'] = cpu
	task_state[tid]['sys'][cpu] = 0
	task_state[tid]['user'][cpu] = 0
	task_state[tid]['idle'][cpu] = 0
	task_state[tid]['busy-unknown'][cpu] = 0

def change_mode(mode, tid, timestamp):
	cpu = task_state[tid]['cpu']
	delta = timestamp - task_state[tid]['timestamp']
	task_state[tid][task_state[tid]['mode']][cpu] += delta
	if tid != 0:
		debug_print("task %s %s(%u) = %f + %f = %f" % (tid, task_state[tid]['mode'], cpu, task_state[tid][task_state[tid]['mode']][cpu] - delta, delta, task_state[tid][task_state[tid]['mode']][cpu]))
		debug_print("task %s now %s" % (tid, mode))
	task_state[tid]['mode'] = mode
	task_state[tid]['timestamp'] = timestamp

def raw_syscalls__sys_enter(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, id, args, perf_sample_dict):
	common_pid = perf_sample_dict['sample']['pid']
	common_tid = perf_sample_dict['sample']['tid']
	global beginTimestamp
	global endTimestamp
	if (beginTimestamp == 0):
		beginTimestamp = msecs(common_secs,common_nsecs)
	endTimestamp = msecs(common_secs,common_nsecs)

	debug_print("%07u.%09u %9s %d:%d [%d] %s" % (common_secs, common_nsecs, 'enter', common_pid, common_tid, common_cpu, syscall_name(id)))

	if common_tid not in task_info.keys():
		new_task(common_tid, common_pid, common_comm)
		# time before now should count as "pending user"
		task_info[task]['timestamp'] = beginTimestamp
		task_info[task]['mode'] = 'user'

	if common_cpu not in task_state[common_tid]['sys'].keys():
		new_tid_cpu(common_tid, common_cpu)

	if task_state[common_tid]['mode'] == 'sys':
		print "re-entered! syscall from signal handler??"
		sys.exit(0)

	if task_state[common_tid]['mode'] == 'busy-unknown':
		task_state[common_tid]['mode'] = 'user'
		for cpu in task_state[common_tid]['busy-unknown'].keys():
			task_state[common_tid]['user'][cpu] = task_state[common_tid]['busy-unknown'][cpu] 
			task_state[common_tid]['busy-unknown'][cpu] = 0
		pending = True

	task_state[common_tid]['cpu'] = common_cpu
	task_state[common_tid]['id'] = id
	task_state[common_tid]['sys_enter'] = endTimestamp
	if id not in task_state[common_tid]['count'].keys():
		task_state[common_tid]['min'][id] = 999999999
		task_state[common_tid]['max'][id] = 0
		task_state[common_tid]['count'][id] = 0
		task_state[common_tid]['elapsed'][id] = 0
		task_state[common_tid]['pending'][id] = 0
	change_mode('sys',common_tid,endTimestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def raw_syscalls__sys_exit(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, id, ret, perf_sample_dict):
	common_pid = perf_sample_dict['sample']['pid']
	common_tid = perf_sample_dict['sample']['tid']
	global beginTimestamp
	global endTimestamp
	if ( beginTimestamp == 0):
		beginTimestamp = msecs(common_secs,common_nsecs)
	endTimestamp = msecs(common_secs,common_nsecs)

	debug_print("%07u.%09u %9s %u:%u [%u] %u:%s" % (common_secs, common_nsecs, 'exit', common_pid, common_tid, common_cpu, id, syscall_name(id)))

	pending = False
	if common_tid not in task_info.keys():
		new_task(common_tid, common_pid, common_comm)
		task_state[common_tid]['cpu'] = common_cpu
		task_state[common_tid]['mode'] = 'sys'
		task_state[common_tid]['id'] = id
		task_state[common_tid]['timestamp'] = beginTimestamp
		pending = True

	# sched_setaffinity, at least, can migrate a task without triggering
	# a sched_migrate_task event
	if common_cpu != task_state[common_tid]['cpu']:
		task_state[common_tid]['migrations'] += 1

	if common_cpu not in task_state[common_tid]['sys']:
		new_tid_cpu(common_tid, common_cpu)

	if task_state[common_tid]['mode'] == 'busy-unknown':
		task_state[common_tid]['mode'] = 'sys'
		for cpu in task_state[common_tid]['busy-unknown'].keys():
			task_state[common_tid]['sys'][cpu] = task_state[common_tid]['busy-unknown'][cpu] 
			task_state[common_tid]['busy-unknown'][cpu] = 0
		pending = True

	if id not in task_state[common_tid]['count'].keys():
		task_state[common_tid]['count'][id] = 0
		task_state[common_tid]['elapsed'][id] = 0
		task_state[common_tid]['pending'][id] = 0
		task_state[common_tid]['min'][id] = 999999999
		task_state[common_tid]['max'][id] = 0

	# commented out because sometimes syscalls, like futex, go idle (sched_switch),
	# then the next event is sys_exit
	#if task_state[common_tid]['mode'] != 'sys':
	#	debug_print("spurious exit?! mode was %s" % (task_state[common_tid]['mode']))
	#	sys.exit(0)

	if pending:
		task_state[common_tid]['pending'][id] = endTimestamp - beginTimestamp
		debug_print("task %u syscall %s pending time %fms" % (common_tid, syscall_name(id), task_state[common_tid]['pending'][id]))
	else:
		delta = endTimestamp - task_state[common_tid]['sys_enter']
		task_state[common_tid]['count'][id] += 1
		task_state[common_tid]['elapsed'][id] += delta 
		debug_print("delta = %f min = %f max = %f" % (delta, task_state[common_tid]['min'][id], task_state[common_tid]['max'][id]))
		if delta < task_state[common_tid]['min'][id]:
			debug_print("task %u %s min %f" % (common_tid, syscall_name(id), delta))
			task_state[common_tid]['min'][id] = delta
		if delta > task_state[common_tid]['max'][id]:
			debug_print("task %u %s max %f" % (common_tid, syscall_name(id), delta))
			task_state[common_tid]['max'][id] = delta
		debug_print("task %u syscall %s count %u time %fms elapsed %fms" % (common_tid, syscall_name(id), task_state[common_tid]['count'][id], delta, task_state[common_tid]['elapsed'][id]))

	if task_state[common_tid]['cpu'] != common_cpu:
		debug_print("migration within syscall!")
		task_state[common_tid]['migrations'] += 1
		delta /= 2
		debug_print("task %u migrations %u sys %f + %f = %f" % (common_tid, task_state[common_tid]['migrations'], task_state[common_tid]['sys'][task_state[common_tid]['cpu']] - delta, delta, task_state[common_tid]['sys'][task_state[common_tid]['cpu']]))
		task_state[common_tid]['sys'][task_state[common_tid]['cpu']] += delta
		task_state[common_tid]['timestamp'] += delta

	change_mode('user',common_tid,endTimestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def sched__sched_switch(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
	next_comm, next_pid, next_prio, perf_sample_dict):
	common_pid = perf_sample_dict['sample']['pid']
	common_tid = perf_sample_dict['sample']['tid']

	global beginTimestamp
	global endTimestamp
	if ( beginTimestamp == 0):
		beginTimestamp = msecs(common_secs,common_nsecs)
	endTimestamp = msecs(common_secs,common_nsecs)

	debug_print("%07u.%09u %9s %u:%s %u:%s" % (common_secs, common_nsecs, 'switch', prev_pid, task_state[prev_pid]['mode'], next_pid, task_state[next_pid]['mode']))

	if prev_pid not in task_info.keys():
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(prev_pid, prev_pid, prev_comm)
		task_state[prev_pid]['cpu'] = common_cpu
		task_state[prev_pid]['mode'] = 'busy-unknown'
		task_state[prev_pid]['resume-mode'] = 'busy-unknown'
		task_state[prev_pid]['timestamp'] = beginTimestamp
		task_state[prev_pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[prev_pid]['sys'].keys():
		new_tid_cpu(prev_pid, common_cpu)

	task_state[prev_pid]['resume-mode'] = task_state[prev_pid]['mode']
	change_mode('idle', prev_pid, endTimestamp)

	if next_pid not in task_info.keys():
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(next_pid, next_pid, next_comm)
		task_state[next_pid]['cpu'] = common_cpu
		task_state[next_pid]['mode'] = 'idle'
		task_state[next_pid]['resume-mode'] = 'busy-unknown'
		task_state[next_pid]['timestamp'] = beginTimestamp
		task_state[next_pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[next_pid]['idle'].keys():
		new_tid_cpu(next_pid, common_cpu)

	task_state[next_pid]['cpu'] = common_cpu

	# what if 'resume-mode' isn't set?
	# we have to wait to determine the mode and treat it as pending...
	change_mode(task_state[next_pid]['resume-mode'], next_pid, endTimestamp)

	if params.debug:
		print_syscall_totals([prev_pid, next_pid])

def sched__sched_migrate_task(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, orig_cpu, 
	dest_cpu, perf_sample_dict):
	common_pid = perf_sample_dict['sample']['pid']
	common_tid = perf_sample_dict['sample']['tid']

	global beginTimestamp
	global endTimestamp
	if ( beginTimestamp == 0):
		beginTimestamp = msecs(common_secs,common_nsecs)
	endTimestamp = msecs(common_secs,common_nsecs)

	debug_print("%07u.%09u %9s pid=%u, orig_cpu=%u, dest_cpu=%u" % (common_secs, common_nsecs, 'migrate', pid, orig_cpu, dest_cpu))

	if orig_cpu == dest_cpu:
		return

	if pid not in task_info.keys():
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(pid, pid, comm)
		task_state[pid]['cpu'] = orig_cpu
		task_state[pid]['mode'] = 'idle'
		task_state[pid]['resume-mode'] = 'busy-unknown'
		task_state[pid]['timestamp'] = beginTimestamp
		task_state[pid]['busy-unknown'][orig_cpu] = 0

	if orig_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, orig_cpu)

	task_state[pid]['migrations'] += 1

	change_mode(task_state[pid]['mode'], pid, endTimestamp)
	if dest_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, dest_cpu)
	task_state[pid]['cpu'] = dest_cpu

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_process_exec(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, filename, pid, old_pid, perf_sample_dict):
	common_pid = perf_sample_dict['sample']['pid']
	common_tid = perf_sample_dict['sample']['tid']

	global beginTimestamp
	global endTimestamp
	if ( beginTimestamp == 0):
		beginTimestamp = msecs(common_secs,common_nsecs)
	endTimestamp = msecs(common_secs,common_nsecs)

	debug_print("%07u.%09u %9s filename=%s, pid=%d, old_pid=%d" % (common_secs, common_nsecs, 'exec', filename, pid, old_pid))

	if old_pid not in task_info.keys():
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(old_pid, old_pid, common_comm)
		task_state[old_pid]['cpu'] = common_cpu
		task_state[old_pid]['mode'] = 'sys'
		task_state[old_pid]['timestamp'] = beginTimestamp
		task_state[old_pid]['sys'][common_cpu] = 0
		task_state[old_pid]['user'][common_cpu] = 0
		task_state[old_pid]['idle'][common_cpu] = 0
		task_state[old_pid]['busy-unknown'][common_cpu] = 0
		task_state[old_pid]['pending'][common_cpu] = 0

	if common_cpu not in task_state[old_pid]['sys'].keys():
		new_tid_cpu(old_pid, common_cpu)

	# close out current task stats and stow them somewhere,
	# because we're reusing the TID for a new process image,
	# for which we need to start new task stats

	change_mode('exit', old_pid, endTimestamp)

	suffix=0
	while True:
		task = str(old_pid)+"-"+str(suffix)
		if task in task_info.keys():
			suffix += 1
		else:
			break
	debug_print("\"new\" task \"%s\"" % (task))

	task_info[task]['pid'] = task_info[old_pid]['pid']
	task_info[task]['comm'] = task_info[old_pid]['comm']
	task_state[task]['mode'] = 'exit'
	task_state[task]['migrations'] = task_state[old_pid]['migrations']
	for cpu in sorted(task_state[old_pid]['sys'].keys()):
		task_state[task]['user'][cpu] = task_state[old_pid]['user'][cpu]
		task_state[task]['sys'][cpu] = task_state[old_pid]['sys'][cpu]
		task_state[task]['idle'][cpu] = task_state[old_pid]['idle'][cpu]
		task_state[task]['busy-unknown'][cpu] = task_state[old_pid]['busy-unknown'][cpu]
	for id in task_state[old_pid]['count'].keys():
		task_state[task]['count'][id] = task_state[old_pid]['count'][id]
		task_state[task]['elapsed'][id] = task_state[old_pid]['elapsed'][id]
		task_state[task]['pending'][id] = task_state[old_pid]['pending'][id]
		task_state[task]['min'][id] = task_state[old_pid]['min'][id]
		task_state[task]['max'][id] = task_state[old_pid]['max'][id]

	if params.debug:
		print_syscall_totals([old_pid])
		print_syscall_totals([task])

	del task_info[old_pid]
	del task_state[old_pid]
	new_task(common_pid, pid, common_comm)
	task_state[pid]['mode'] = 'idle'
	task_state[pid]['timestamp'] = msecs(common_secs,common_nsecs)
	perf_sample_dict['sample']['tid'] = pid
	EXEC = 11
	# args is not used by the caller, or we're in trouble
	raw_syscalls__sys_enter(event_name, context, common_cpu, common_secs, common_nsecs, pid, common_comm, common_callchain, EXEC, 'args', perf_sample_dict)

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_process_fork(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, parent_comm, parent_pid, child_comm, child_pid, perf_sample_dict):
	common_pid = perf_sample_dict['sample']['pid']
	common_tid = perf_sample_dict['sample']['tid']

	global beginTimestamp
	global endTimestamp
	if ( beginTimestamp == 0):
		beginTimestamp = msecs(common_secs,common_nsecs)
	endTimestamp = msecs(common_secs,common_nsecs)

	debug_print("%07u.%09u %9s [%u:%u] [%u] (parent_pid=%u)" % (common_secs, common_nsecs, 'fork', common_pid, common_tid, child_pid, parent_pid))

	new_task(child_pid, common_pid, common_comm)
	new_tid_cpu(child_pid, common_cpu)
	task_state[child_pid]['mode'] = 'idle'
	task_state[child_pid]['timestamp'] = endTimestamp
	CLONE = 120
	id = CLONE
	task_state[child_pid]['cpu'] = common_cpu
	task_state[child_pid]['resume-mode'] = 'sys'
	task_state[child_pid]['id'] = id
	task_state[child_pid]['sys_enter'] = endTimestamp
	task_state[child_pid]['min'][id] = 999999999
	task_state[child_pid]['max'][id] = 0
	task_state[child_pid]['count'][id] = 0
	task_state[child_pid]['elapsed'][id] = 0
	task_state[child_pid]['pending'][id] = 0

	if params.debug:
		print_syscall_totals([common_tid, child_pid])

def sched__sched_process_exit(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, perf_sample_dict):
	common_pid = perf_sample_dict['sample']['pid']
	common_tid = perf_sample_dict['sample']['tid']

	global beginTimestamp
	global endTimestamp
	if ( beginTimestamp == 0):
		beginTimestamp = msecs(common_secs,common_nsecs)
	endTimestamp = msecs(common_secs,common_nsecs)

	debug_print("%07u.%09u %9s %u" % (common_secs, common_nsecs, 'exit', common_tid))
	change_mode('exit', common_tid, endTimestamp)
	task_state[common_tid]['exit'][common_cpu] = 0

	if params.debug:
		print_syscall_totals([common_tid])

#def trace_unhandled(event_name, context, event_fields_dict):
#	pass

def print_syscall_totals(tidlist):
	debug_print("print_syscall_totals(" + str(tidlist) + ")")
	pids = []
	for task in sorted(tidlist):
		pid = task_info[task]['pid']
		if pid not in pids:	
			 pids.append(pid)
	print "-- PID:"
	all_user = 0
	all_sys = 0
	all_idle = 0
	all_busy = 0
	all_migrations = 0
	for pid in sorted(pids):
		if pid == 0:
			continue
		print "%6u:" % (pid)
		proc_user = 0
		proc_sys = 0
		proc_idle = 0
		proc_busy = 0
		proc_migrations = 0
		for task in sorted(tidlist):
			if task_info[task]['pid'] == pid:
				print "     -- [%8s] %-20s %3s %12s %12s %12s %12s %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "busy", "idle", "util", "moves")
				task_user = 0
				task_sys = 0
				task_idle = 0
				task_busy = 0
				task_migrations = task_state[task]['migrations']
				# each "comm" is delivered as a bytearray:
				#   the actual command, a null terminator, and garbage
				# "print" wants to splat every byte, including the garbage
				# so, truncate the bytearray at the null
				comm = null(task_info[task]['comm'])
				for cpu in sorted(task_state[task]['sys'].keys()):
					print "\t[%8s] %-20s %3u %12.6f %12.6f %12.6f %12.6f" % (task, comm, cpu, task_state[task]['user'][cpu], task_state[task]['sys'][cpu], task_state[task]['busy-unknown'][cpu], task_state[task]['idle'][cpu])
					task_user += task_state[task]['user'][cpu]
					task_sys += task_state[task]['sys'][cpu]
					task_idle += task_state[task]['idle'][cpu]
					task_busy += task_state[task]['busy-unknown'][cpu]
					task_running = task_user + task_sys + task_busy
				print "\t[%8s] %-20s ALL %12.6f %12.6f %12.6f %12.6f %5.1f%% %6u" % (task, comm, task_user, task_sys, task_busy, task_idle, task_running * 100 / (task_running + task_idle) if task_running > 0 else 0, task_migrations)
				print
				if task_state[task]['count']:
					print "\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("id", "name", "count", "elapsed", "pending", "average", "minimum", "maximum")
					for id in sorted(task_state[task]['count'].keys(), key= lambda x: (task_state[task]['count'][x], task_state[task]['elapsed'][x]), reverse=True):
						count = task_state[task]['count'][id]
						elapsed = task_state[task]['elapsed'][id]
						pending = task_state[task]['pending'][id]
						min = task_state[task]['min'][id]
						max = task_state[task]['max'][id]
						print "\t\t(%3u)%-20s %6u %12.6f %12.6f" % (id, syscall_name(id), count, elapsed, pending),
						if count > 0:
							print " %12.6f %12.6f %12.6f" % (elapsed/count, min, max)
						else:
							print " %12s %12s %12s" % ("--", "--", "--")
						if id not in task_state['ALL']['count'].keys():
							task_state['ALL']['count'][id] = 0
							task_state['ALL']['elapsed'][id] = 0
							task_state['ALL']['pending'][id] = 0
							task_state['ALL']['max'][id] = 0
							task_state['ALL']['min'][id] = 999999999
						task_state['ALL']['count'][id] += count
						task_state['ALL']['elapsed'][id] += elapsed
						task_state['ALL']['pending'][id] += pending
						if min < task_state['ALL']['min'][id]:
							task_state['ALL']['min'][id] = min
						if max > task_state['ALL']['max'][id]:
							task_state['ALL']['max'][id] = max
					print
				proc_user += task_user
				proc_sys += task_sys
				proc_idle += task_idle
				proc_busy += task_busy
				proc_migrations += task_migrations
		all_user += proc_user
		all_sys += proc_sys
		all_idle += proc_idle
		all_busy += proc_busy
		all_migrations += proc_migrations
		print "     -- [%8s] %-20s %3s %12s %12s %12s %12s %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "busy", "idle", "util", "moves")
		print "\t[     ALL] %-20s ALL %12.6f %12.6f %12.6f %12.6f %5.1f%% %6u" % ("", proc_user, proc_sys, proc_busy, proc_idle, (proc_user + proc_sys + proc_busy) * 100 / (proc_user + proc_sys + proc_busy + proc_idle) if proc_user + proc_sys + proc_busy > 0 else 0, proc_migrations)

	print
	print "%6s:" % ("ALL")
	print "     -- [%8s] %-20s %3s %12s %12s %12s %12s %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "busy", "idle", "util", "moves")
	print "\t[     ALL] %-20s ALL %12.6f %12.6f %12.6f %12.6f %5.1f%% %6u" % ("", all_user, all_sys, all_busy, all_idle, (all_user + all_sys + all_busy) * 100 / (all_user + all_sys + all_busy + all_idle) if all_user + all_sys + all_busy > 0 else 0, all_migrations)
	print
	print "\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("id", "name", "count", "elapsed", "pending", "average", "minimum", "maximum")
	for id in sorted(task_state['ALL']['count'].keys(), key= lambda x: (task_state['ALL']['count'][x], task_state['ALL']['elapsed'][x]), reverse=True):
		print "\t\t(%3u)%-20s %6u %12.6f+%12.6f" % (id, syscall_name(id), task_state['ALL']['count'][id], task_state['ALL']['elapsed'][id], task_state['ALL']['pending'][id]),
		if task_state['ALL']['count'][id] > 0:
			print " %12.6f %12.6f %12.6f" % (task_state['ALL']['elapsed'][id]/task_state['ALL']['count'][id], task_state['ALL']['min'][id], task_state['ALL']['max'][id])
		else:
			print " %12s %12s %12s" % ("--", "--", "--")
	print
	print "Total Trace Time: %f msec" % (endTimestamp - beginTimestamp)

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

global start_timestamp, curr_timestamp

task_state = autodict()
task_info = autodict()
task_tids = []

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
	for task in task_tids:
		if task == 0:
			continue

		if task_state[task]['mode'] == 'sys':
			delta = curr_timestamp - task_state[task]['sys_enter']
			id = task_state[task]['id']
			cpu = task_state[task]['cpu']
			task_state[task]['pending'][id] += delta
			task_state[task]['sys'][cpu] += delta
			task_state[task]['runtime'][cpu] += delta
			debug_print("task %u syscall %s pending time %f + %f = %fms" % (task, syscall_name(id), task_state[task]['pending'][id] - delta, delta, task_state[task]['pending'][id]))
			debug_print("task %u (%s) sys time %f + %f = %fms" % (task, syscall_name(id), task_state[task]['sys'][cpu] - delta, delta, task_state[task]['sys'][cpu]))

		elif task_state[task]['mode'] == 'user':
			delta = curr_timestamp - task_state[task]['timestamp']
			cpu = task_state[task]['cpu']
			task_state[task]['user'][cpu] += delta
			task_state[task]['runtime'][cpu] += delta
			debug_print("task %u user time %f + %f = %fms" % (task, task_state[task]['user'][cpu] - delta, delta, task_state[task]['user'][cpu]))

		elif task_state[task]['mode'] == 'idle':
			delta = curr_timestamp - task_state[task]['timestamp']
			cpu = task_state[task]['cpu']
			task_state[task]['idle'][cpu] += delta
			task_state[task]['unaccounted'][cpu] += delta
			debug_print("task %u idle time %f + %f = %fms" % (task, task_state[task]['idle'][cpu] - delta, delta, task_state[task]['idle'][cpu]))
			# what if 'resume-mode' isn't set?
			# ...which is pretty likely if we're here and still 'busy-unknown'
			if task_state[task]['resume-mode'] == 'sys':
				delta = curr_timestamp - task_state[task]['sys_enter']
				id = task_state[task]['id']
				cpu = task_state[task]['cpu']
				task_state[task]['pending'][id] += delta
				debug_print("task %u syscall %s pending time %f + %f = %fms" % (task, syscall_name(id), task_state[task]['pending'][id] - delta, delta, task_state[task]['pending'][id]))

		elif task_state[task]['mode'] == 'busy-unknown':
			delta = curr_timestamp - task_state[task]['timestamp']
			cpu = task_state[task]['cpu']
			task_state[task]['busy-unknown'][cpu] += delta
			task_state[task]['unaccounted'][cpu] += delta
			debug_print("task %u busy-unknown %f + %f = %fms" % (task, task_state[task]['busy-unknown'][cpu] - delta, delta, task_state[task]['busy-unknown'][cpu]))

	print_syscall_totals(task_tids)

start_timestamp = 0
curr_timestamp = 0

def ns2ms(nsecs):
	return nsecs * 0.000001

def new_task(tid, pid, comm, timestamp, mode):
	if tid != 0:
		debug_print("new task %u (%s:%s)" % (tid, str(pid), null(comm)))
	task_info[tid]['pid'] = pid
	task_info[tid]['comm'] = comm
	task_state[tid]['timestamp'] = timestamp
	task_state[tid]['mode'] = mode
	task_state[tid]['migrations'] = 0
	task_state[tid]['sched_stat'] = False
	task_tids.append(tid);

def new_tid_cpu(tid, cpu):
	if tid != 0:
		debug_print("new CPU %d for task %u" % (cpu, tid))
	task_state[tid]['cpu'] = cpu
	task_state[tid]['sys'][cpu] = 0
	task_state[tid]['user'][cpu] = 0
	task_state[tid]['idle'][cpu] = 0
	task_state[tid]['busy-unknown'][cpu] = 0
	task_state[tid]['runtime'][cpu] = 0 
	task_state[tid]['sleep'][cpu] = 0 
	task_state[tid]['wait'][cpu] = 0 
	task_state[tid]['blocked'][cpu] = 0 
	task_state[tid]['iowait'][cpu] = 0 
	task_state[tid]['unaccounted'][cpu] = 0 

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
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %9s %d:%d [%d] %s" % (common_secs, common_nsecs, 'enter', common_pid, common_tid, common_cpu, syscall_name(id)))

	if common_tid not in task_tids:
		new_task(common_tid, common_pid, common_comm, start_timestamp, 'user')
		# time before now should count as "pending user"
	elif task_info[common_tid]['pid'] == 'unknown':
		task_info[common_tid]['pid'] = common_pid

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
	task_state[common_tid]['sys_enter'] = curr_timestamp
	if id not in task_state[common_tid]['count'].keys():
		task_state[common_tid]['min'][id] = 999999999
		task_state[common_tid]['max'][id] = 0
		task_state[common_tid]['count'][id] = 0
		task_state[common_tid]['elapsed'][id] = 0
		task_state[common_tid]['pending'][id] = 0
	change_mode('sys',common_tid,curr_timestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def raw_syscalls__sys_exit(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, id, ret, perf_sample_dict):
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %9s %u:%u [%u] %u:%s" % (common_secs, common_nsecs, 'exit', common_pid, common_tid, common_cpu, id, syscall_name(id)))

	pending = False
	if common_tid not in task_tids:
		new_task(common_tid, common_pid, common_comm, start_timestamp, 'sys')
		task_state[common_tid]['cpu'] = common_cpu
		task_state[common_tid]['id'] = id
		pending = True
	elif task_info[common_tid]['pid'] == 'unknown':
		task_info[common_tid]['pid'] = common_pid

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
		task_state[common_tid]['pending'][id] = curr_timestamp - start_timestamp
		debug_print("task %u syscall %s pending time %fms" % (common_tid, syscall_name(id), task_state[common_tid]['pending'][id]))
	else:
		delta = curr_timestamp - task_state[common_tid]['sys_enter']
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

	change_mode('user',common_tid,curr_timestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def sched__sched_switch(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
	next_comm, next_pid, next_prio, perf_sample_dict):
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %9s %u:%s %u:%s" % (common_secs, common_nsecs, 'switch', prev_pid, task_state[prev_pid]['mode'], next_pid, task_state[next_pid]['mode']))

	if prev_pid not in task_tids:
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(prev_pid, 'unknown', prev_comm, start_timestamp, 'busy-unknown')
		task_state[prev_pid]['cpu'] = common_cpu
		task_state[prev_pid]['resume-mode'] = 'busy-unknown'
		task_state[prev_pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[prev_pid]['sys'].keys():
		new_tid_cpu(prev_pid, common_cpu)

	if task_state[prev_pid]['sched_stat'] == False:
		task_state[prev_pid]['sched_stat'] = True
		task_state[prev_pid]['runtime'][common_cpu] = curr_timestamp - start_timestamp
		debug_print("%7s.%9s runtime = %u" % ("", "", task_state[prev_pid]['runtime'][common_cpu]))

	task_state[prev_pid]['resume-mode'] = task_state[prev_pid]['mode']
	change_mode('idle', prev_pid, curr_timestamp)

	if next_pid not in task_tids:
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(next_pid, 'unknown', next_comm, start_timestamp, 'idle')
		task_state[next_pid]['cpu'] = common_cpu
		task_state[next_pid]['resume-mode'] = 'busy-unknown'
		task_state[next_pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[next_pid]['idle'].keys():
		new_tid_cpu(next_pid, common_cpu)

	if task_state[next_pid]['sched_stat'] == False:
		task_state[next_pid]['sched_stat'] = True
		task_state[next_pid]['unaccounted'][common_cpu] = curr_timestamp - start_timestamp
		debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[next_pid]['unaccounted'][common_cpu]))

	task_state[next_pid]['cpu'] = common_cpu

	# what if 'resume-mode' isn't set?
	# we have to wait to determine the mode and treat it as pending...
	change_mode(task_state[next_pid]['resume-mode'], next_pid, curr_timestamp)

	if params.debug:
		print_syscall_totals([prev_pid, next_pid])

def sched__sched_migrate_task(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, orig_cpu, 
	dest_cpu, perf_sample_dict):
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %9s pid=%u, orig_cpu=%u, dest_cpu=%u" % (common_secs, common_nsecs, 'migrate', pid, orig_cpu, dest_cpu))

	if orig_cpu == dest_cpu:
		return

	if pid not in task_tids:
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(pid, 'unknown', comm, start_timestamp, 'idle')
		task_state[pid]['cpu'] = orig_cpu
		task_state[pid]['resume-mode'] = 'busy-unknown'
		task_state[pid]['busy-unknown'][orig_cpu] = 0

	if orig_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, orig_cpu)

	task_state[pid]['migrations'] += 1

	change_mode(task_state[pid]['mode'], pid, curr_timestamp)
	if dest_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, dest_cpu)
	task_state[pid]['cpu'] = dest_cpu

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_process_exec(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, filename, pid, old_pid, perf_sample_dict):
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %9s filename=%s, pid=%d, old_pid=%d" % (common_secs, common_nsecs, 'exec', filename, pid, old_pid))

	if old_pid not in task_tids:
		# I don't have a real PID here... hmm
		# new_task(next_pid, ?, next_comm)
		# self-parenting for now...
		new_task(old_pid, 'unknown', common_comm, start_timestamp, 'sys')
		task_state[old_pid]['cpu'] = common_cpu
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

	change_mode('exit', old_pid, curr_timestamp)

	suffix=0
	while True:
		task = str(old_pid)+"-"+str(suffix)
		if task in task_tids:
			suffix += 1
		else:
			break
	debug_print("\"new\" task \"%s\"" % (task))

	task_info[task]['pid'] = task_info[old_pid]['pid']
	task_info[task]['comm'] = task_info[old_pid]['comm']
	task_tids.append(task)
	task_state[task]['mode'] = 'exit'
	task_state[task]['migrations'] = task_state[old_pid]['migrations']
	for cpu in sorted(task_state[old_pid]['sys'].keys()):
		task_state[task]['user'][cpu] = task_state[old_pid]['user'][cpu]
		task_state[task]['sys'][cpu] = task_state[old_pid]['sys'][cpu]
		task_state[task]['idle'][cpu] = task_state[old_pid]['idle'][cpu]
		task_state[task]['busy-unknown'][cpu] = task_state[old_pid]['busy-unknown'][cpu]
		task_state[task]['runtime'][cpu] = task_state[old_pid]['runtime'][cpu]
		task_state[task]['sleep'][cpu] = task_state[old_pid]['sleep'][cpu]
		task_state[task]['wait'][cpu] = task_state[old_pid]['wait'][cpu]
		task_state[task]['blocked'][cpu] = task_state[old_pid]['blocked'][cpu]
		task_state[task]['iowait'][cpu] = task_state[old_pid]['iowait'][cpu]
		task_state[task]['unaccounted'][cpu] = task_state[old_pid]['unaccounted'][cpu]
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
	task_tids.remove(old_pid)
	del task_state[old_pid]
	new_task(common_pid, pid, common_comm, curr_timestamp, 'idle')
	task_state[pid]['sched_stat'] = True
	perf_sample_dict['sample']['tid'] = pid
	EXEC = 11
	# args is not used by the caller, or we're in trouble
	raw_syscalls__sys_enter(event_name, context, common_cpu, common_secs, common_nsecs, pid, common_comm, common_callchain, EXEC, 'args', perf_sample_dict)

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_process_fork(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, parent_comm, parent_pid, child_comm, child_pid, perf_sample_dict):
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %9s [%u:%u] [%u] (parent_pid=%u)" % (common_secs, common_nsecs, 'fork', common_pid, common_tid, child_pid, parent_pid))

	new_task(child_pid, common_pid, common_comm, curr_timestamp, 'idle')
	new_tid_cpu(child_pid, common_cpu)
	task_state[child_pid]['sched_stat'] = True
	CLONE = 120
	id = CLONE
	task_state[child_pid]['cpu'] = common_cpu
	task_state[child_pid]['resume-mode'] = 'sys'
	task_state[child_pid]['id'] = id
	task_state[child_pid]['sys_enter'] = curr_timestamp
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
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %9s %u" % (common_secs, common_nsecs, 'exit', common_tid))
	change_mode('exit', common_tid, curr_timestamp)
	task_state[common_tid]['exit'][common_cpu] = 0

	if params.debug:
		print_syscall_totals([common_tid])

def sched__sched_stat_runtime(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, runtime, vruntime, 
		perf_sample_dict):
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%7u.%09u sched_stat_runtime(%u,%s,%u,%u) in %s" % (common_secs,common_nsecs,pid,null(comm),runtime,vruntime,task_state[pid]['mode']))
	if pid not in task_tids:
		new_task(pid, 'unknown', comm, start_timestamp, 'busy-unknown')
		# time before now should count as "pending runtime"
		task_state[pid]['cpu'] = common_cpu
		task_state[pid]['resume-mode'] = 'busy-unknown'
		task_state[pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, common_cpu)

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if runtime > curr_timestamp - start_timestamp:
			runtime = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][common_cpu] = curr_timestamp - start_timestamp - runtime
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][common_cpu]))

	debug_print("%7s.%9s runtime %u + %u = %u" % ("", "", task_state[pid]['runtime'][common_cpu], runtime, task_state[pid]['runtime'][common_cpu] + runtime))
	task_state[pid]['runtime'][common_cpu] += runtime

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_stat_blocked(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%7u.%09u sched_stat_blocked(%u,%s,%u) in %s" % (common_secs,common_nsecs,pid,null(comm),delay,task_state[pid]['mode']))
	if pid not in task_tids:
		new_task(pid, 'unknown', comm, start_timestamp, 'idle')
		# time before now should count as "pending blocked"
		task_state[pid]['cpu'] = common_cpu
		task_state[pid]['resume-mode'] = 'busy-unknown'
		task_state[pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, common_cpu)

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][common_cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][common_cpu]))

	debug_print("%7s.%9s blocked %u + %u = %u" % ("", "", task_state[pid]['blocked'][common_cpu], delay, task_state[pid]['blocked'][common_cpu] + delay))
	task_state[pid]['blocked'][common_cpu] += delay

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_stat_iowait(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%7u.%09u sched_stat_iowait (%u,%s,%u) in %s" % (common_secs,common_nsecs,pid,null(comm),delay,task_state[pid]['mode']))
	if pid not in task_tids:
		new_task(pid, 'unknown', comm, start_timestamp, 'idle')
		# time before now should count as "pending iowait"
		task_state[pid]['cpu'] = common_cpu
		task_state[pid]['resume-mode'] = 'busy-unknown'
		task_state[pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, common_cpu)

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][common_cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][common_cpu]))

	debug_print("%7s.%9s iowait %u + %u = %u" % ("", "", task_state[pid]['iowait'][common_cpu], delay, task_state[pid]['iowait'][common_cpu] + delay))
	task_state[pid]['iowait'][common_cpu] += delay

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_stat_wait(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%7u.%09u sched_stat_wait   (%u,%s,%u) in %s" % (common_secs,common_nsecs,pid,null(comm),delay,task_state[pid]['mode']))
	if pid not in task_tids:
		new_task(pid, 'unknown', comm, start_timestamp, 'idle')
		# time before now should count as "pending wait"
		task_state[pid]['cpu'] = common_cpu
		task_state[pid]['resume-mode'] = 'busy-unknown'
		task_state[pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, common_cpu)

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][common_cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][common_cpu]))

	debug_print("%7s.%9s wait %u + %u = %u" % ("", "", task_state[pid]['wait'][common_cpu], delay, task_state[pid]['wait'][common_cpu] + delay))
	task_state[pid]['wait'][common_cpu] += delay

	if params.debug:
		print_syscall_totals([pid])

def sched__sched_stat_sleep(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, delay, perf_sample_dict):
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%7u.%09u sched_stat_sleep  (%u,%s,%u) in %s" % (common_secs,common_nsecs,pid,null(comm),delay,task_state[pid]['mode']))
	if pid not in task_tids:
		new_task(pid, 'unknown', comm, start_timestamp, 'idle')
		# time before now should count as "pending sleep"
		task_state[pid]['cpu'] = common_cpu
		task_state[pid]['resume-mode'] = 'busy-unknown'
		task_state[pid]['busy-unknown'][common_cpu] = 0

	if common_cpu not in task_state[pid]['sys'].keys():
		new_tid_cpu(pid, common_cpu)

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][common_cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][common_cpu]))

	debug_print("%7s.%9s sleep %u + %u = %u" % ("", "", task_state[pid]['sleep'][common_cpu], delay, task_state[pid]['sleep'][common_cpu] + delay))
	task_state[pid]['sleep'][common_cpu] += delay

	if params.debug:
		print_syscall_totals([pid])

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
	all_runtime = 0
	all_sleep = 0
	all_wait = 0
	all_blocked = 0
	all_iowait = 0
	all_unaccounted = 0
	all_migrations = 0
	for pid in sorted(pids):
		if pid == 0:
			continue
		print "%6s:" % (str(pid))
		proc_user = 0
		proc_sys = 0
		proc_idle = 0
		proc_busy = 0
		proc_runtime = 0
		proc_sleep = 0
		proc_wait = 0
		proc_blocked = 0
		proc_iowait = 0
		proc_unaccounted = 0
		proc_migrations = 0
		for task in sorted(tidlist):
			if task_info[task]['pid'] == pid:
				print "     -- [%8s] %-20s %3s %12s %12s %12s %12s | %12s %12s %12s %12s %12s %12s | %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "busy", "idle", "runtime", "sleep", "wait", "blocked", "iowait", "unaccounted", "util", "moves")
				task_user = 0
				task_sys = 0
				task_idle = 0
				task_busy = 0
				task_runtime = 0
				task_sleep = 0
				task_wait = 0
				task_blocked = 0
				task_iowait = 0
				task_unaccounted = 0
				task_migrations = task_state[task]['migrations']
				# each "comm" is delivered as a bytearray:
				#   the actual command, a null terminator, and garbage
				# "print" wants to splat every byte, including the garbage
				# so, truncate the bytearray at the null
				comm = null(task_info[task]['comm'])
				for cpu in sorted(task_state[task]['sys'].keys()):
					print "\t[%8s] %-20s %3u %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f" % (task, comm, cpu, ns2ms(task_state[task]['user'][cpu]), ns2ms(task_state[task]['sys'][cpu]), ns2ms(task_state[task]['busy-unknown'][cpu]), ns2ms(task_state[task]['idle'][cpu]), ns2ms(task_state[task]['runtime'][cpu]), ns2ms(task_state[task]['sleep'][cpu]), ns2ms(task_state[task]['wait'][cpu]), ns2ms(task_state[task]['blocked'][cpu]), ns2ms(task_state[task]['iowait'][cpu]), ns2ms(task_state[task]['unaccounted'][cpu]))
					task_user += task_state[task]['user'][cpu]
					task_sys += task_state[task]['sys'][cpu]
					task_idle += task_state[task]['idle'][cpu]
					task_busy += task_state[task]['busy-unknown'][cpu]
					task_running = task_user + task_sys + task_busy
					task_runtime += task_state[task]['runtime'][cpu]
					task_sleep += task_state[task]['sleep'][cpu]
					task_wait += task_state[task]['wait'][cpu]
					task_blocked += task_state[task]['blocked'][cpu]
					task_iowait += task_state[task]['iowait'][cpu]
					task_unaccounted += task_state[task]['unaccounted'][cpu]
				print "\t[%8s] %-20s ALL %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f | %5.1f%% %6u" % (task, comm, ns2ms(task_user), ns2ms(task_sys), ns2ms(task_busy), ns2ms(task_idle), ns2ms(task_runtime), ns2ms(task_sleep), ns2ms(task_wait), ns2ms(task_blocked), ns2ms(task_iowait), ns2ms(task_unaccounted), (task_running * 100 / (task_running + task_idle)) if task_running > 0 else 0, task_migrations)
				print
				if task_state[task]['count']:
					print "\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("id", "name", "count", "elapsed", "pending", "average", "minimum", "maximum")
					for id in sorted(task_state[task]['count'].keys(), key= lambda x: (task_state[task]['count'][x], task_state[task]['elapsed'][x]), reverse=True):
						count = task_state[task]['count'][id]
						elapsed = task_state[task]['elapsed'][id]
						pending = task_state[task]['pending'][id]
						min = task_state[task]['min'][id]
						max = task_state[task]['max'][id]
						print "\t\t(%3u)%-20s %6u %12.6f %12.6f" % (id, syscall_name(id), count, ns2ms(elapsed), ns2ms(pending)),
						if count > 0:
							print " %12.6f %12.6f %12.6f" % (ns2ms(elapsed)/count, ns2ms(min), ns2ms(max))
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
				proc_runtime += task_runtime
				proc_sleep += task_sleep
				proc_wait += task_wait
				proc_blocked += task_blocked
				proc_iowait += task_iowait
				proc_unaccounted += task_unaccounted
				proc_migrations += task_migrations
		all_user += proc_user
		all_sys += proc_sys
		all_idle += proc_idle
		all_busy += proc_busy
		all_runtime += proc_runtime
		all_sleep += proc_sleep
		all_wait += proc_wait
		all_blocked += proc_blocked
		all_iowait += proc_iowait
		all_unaccounted += proc_unaccounted
		all_migrations += proc_migrations
		print "     -- [%8s] %-20s %3s %12s %12s %12s %12s | %12s %12s %12s %12s %12s %12s | %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "busy", "idle", "runtime", "sleep", "wait", "blocked", "iowait", "unaccounted", "util", "moves")
		print "\t[     ALL] %-20s ALL %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f | %5.1f%% %6u" % ("", ns2ms(proc_user), ns2ms(proc_sys), ns2ms(proc_busy), ns2ms(proc_idle), ns2ms(proc_runtime), ns2ms(proc_sleep), ns2ms(proc_wait), ns2ms(proc_blocked), ns2ms(proc_iowait), ns2ms(proc_unaccounted), ((proc_user + proc_sys + proc_busy) * 100 / (proc_user + proc_sys + proc_busy + proc_idle)) if proc_user + proc_sys + proc_busy > 0 else 0, proc_migrations)

	print
	print "%6s:" % ("ALL")
	print "     -- [%8s] %-20s %3s %12s %12s %12s %12s | %12s %12s %12s %12s %12s %12s | %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "busy", "idle", "runtime", "sleep", "wait", "blocked", "iowait", "unaccounted", "util", "moves")
	print "\t[     ALL] %-20s ALL %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f | %5.1f%% %6u" % ("", ns2ms(all_user), ns2ms(all_sys), ns2ms(all_busy), ns2ms(all_idle), ns2ms(all_runtime), ns2ms(all_sleep), ns2ms(all_wait), ns2ms(all_blocked), ns2ms(all_iowait), ns2ms(all_unaccounted), ((all_user + all_sys + all_busy) * 100 / (all_user + all_sys + all_busy + all_idle)) if all_user + all_sys + all_busy > 0 else 0, all_migrations)
	print
	print "\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("id", "name", "count", "elapsed", "pending", "average", "minimum", "maximum")
	for id in sorted(task_state['ALL']['count'].keys(), key= lambda x: (task_state['ALL']['count'][x], task_state['ALL']['elapsed'][x]), reverse=True):
		print "\t\t(%3u)%-20s %6u %12.6f %12.6f" % (id, syscall_name(id), task_state['ALL']['count'][id], ns2ms(task_state['ALL']['elapsed'][id]), ns2ms(task_state['ALL']['pending'][id])),
		if task_state['ALL']['count'][id] > 0:
			print " %12.6f %12.6f %12.6f" % (ns2ms(task_state['ALL']['elapsed'][id]/task_state['ALL']['count'][id]), ns2ms(task_state['ALL']['min'][id]), ns2ms(task_state['ALL']['max'][id]))
		else:
			print " %12s %12s %12s" % ("--", "--", "--")
	print
	print "Total Trace Time: %f ms" % ns2ms(curr_timestamp - start_timestamp)

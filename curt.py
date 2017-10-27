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
		
		elif task_state[task]['mode'] == 'hv':
			delta = curr_timestamp - task_state[task]['hcall_enter']
			opcode = task_state[task]['opcode']
			cpu = task_state[task]['cpu']
			task_state[task]['pending_hv'][opcode] += delta
			task_state[task]['hv'][cpu] += delta
			task_state[task]['runtime'][cpu] += delta
			debug_print("task %u hcall %s pending time %f + %f = %fms" % (task, hcall_name(opcode), task_state[task]['pending_hv'][opcode] - delta, delta, task_state[task]['pending_hv'][opcode]))
			debug_print("task %u (%s) hcall time %f + %f = %fms" % (task, hcall_name(opcode), task_state[task]['hv'][cpu] - delta, delta, task_state[task]['hv'][cpu]))

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
	task_state[tid]['resume-mode'] = 'busy-unknown'
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
	task_state[tid]['hv'][cpu] = 0
	task_state[tid]['busy-unknown'][cpu] = 0
	task_state[tid]['runtime'][cpu] = 0 
	task_state[tid]['sleep'][cpu] = 0 
	task_state[tid]['wait'][cpu] = 0 
	task_state[tid]['blocked'][cpu] = 0 
	task_state[tid]['iowait'][cpu] = 0 
	task_state[tid]['unaccounted'][cpu] = 0 

def new_task_syscall(tid, id):
	task_state[tid]['count'][id] = 0
	task_state[tid]['elapsed'][id] = 0
	task_state[tid]['min'][id] = 999999999
	task_state[tid]['max'][id] = 0
	task_state[tid]['pending'][id] = 0

def new_task_hcall(tid, opcode):
	task_state[tid]['count_hv'][opcode] = 0
	task_state[tid]['elapsed_hv'][opcode] = 0
	task_state[tid]['min_hv'][opcode] = 999999999
	task_state[tid]['max_hv'][opcode] = 0
	task_state[tid]['pending_hv'][opcode] = 0

def change_mode(mode, tid, timestamp):
	cpu = task_state[tid]['cpu']
	delta = timestamp - task_state[tid]['timestamp']
	task_state[tid][task_state[tid]['mode']][cpu] += delta
	if tid != 0:
		debug_print("task %s %s(%u) = %u + %u = %u" % (tid, task_state[tid]['mode'], cpu, task_state[tid][task_state[tid]['mode']][cpu] - delta, delta, task_state[tid][task_state[tid]['mode']][cpu]))
		debug_print("task %s now %s" % (tid, mode))
	task_state[tid]['mode'] = mode
	task_state[tid]['timestamp'] = timestamp

def getpid(perf_sample_dict):
	return perf_sample_dict['sample']['pid']

def get_unknown(perf_sample_dict):
	return 'unknown'

def generic_event(event_name, cpu, timestamp, tid, comm, mode, getpid, perf_sample_dict):
	debug_print("%016u %6u [%03u] %-32s" % (timestamp, tid, cpu, event_name))

	if tid not in task_tids:
		new_task(tid, getpid(perf_sample_dict), comm, timestamp, mode)
	elif task_info[tid]['pid'] == 'unknown':
		task_info[tid]['pid'] = getpid(perf_sample_dict)

	if cpu not in task_state[tid][mode].keys():
		new_tid_cpu(tid, cpu)
	elif cpu != task_state[tid]['cpu']:
		task_state[tid]['migrations'] += 1

def raw_syscalls__sys_enter(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, id, args, perf_sample_dict):
	common_tid = common_pid
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s %u [%03u] %s" % (common_secs, common_nsecs, 'sys_enter', common_tid, common_cpu, syscall_name(id)))

	generic_event(event_name, common_cpu, start_timestamp, common_tid, common_comm, 'busy-unknown', getpid, perf_sample_dict)

	if task_state[common_tid]['mode'] == 'sys':
		print "re-entered! syscall from signal handler??"
		sys.exit(0)

	if task_state[common_tid]['mode'] == 'busy-unknown':
		task_state[common_tid]['mode'] = 'user'
		for cpu in task_state[common_tid]['busy-unknown'].keys():
			task_state[common_tid]['user'][cpu] = task_state[common_tid]['busy-unknown'][cpu] 
			task_state[common_tid]['busy-unknown'][cpu] = 0

	task_state[common_tid]['cpu'] = common_cpu
	task_state[common_tid]['id'] = id
	task_state[common_tid]['sys_enter'] = curr_timestamp
	if id not in task_state[common_tid]['count'].keys():
		new_task_syscall(common_tid, id)
	change_mode('sys',common_tid,curr_timestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def raw_syscalls__sys_exit(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, id, ret, perf_sample_dict):
	common_tid = common_pid
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s %u [%03u] %u:%s" % (common_secs, common_nsecs, 'sys_exit', common_tid, common_cpu, id, syscall_name(id)))

	generic_event(event_name, common_cpu, start_timestamp, common_tid, common_comm, 'busy-unknown', getpid, perf_sample_dict)

	pending = False

	if task_state[common_tid]['mode'] == 'busy-unknown':
		task_state[common_tid]['mode'] = 'sys'
		for cpu in task_state[common_tid]['busy-unknown'].keys():
			task_state[common_tid]['sys'][cpu] = task_state[common_tid]['busy-unknown'][cpu] 
			task_state[common_tid]['busy-unknown'][cpu] = 0
		pending = True

	if id not in task_state[common_tid]['count'].keys():
		new_task_syscall(common_tid, id)

	# commented out because sometimes syscalls, like futex, go idle (sched_switch),
	# then the next event is sys_exit
	#if task_state[common_tid]['mode'] != 'sys':
	#	debug_print("spurious exit?! mode was %s" % (task_state[common_tid]['mode']))
	#	sys.exit(0)

	if pending:
		task_state[common_tid]['pending'][id] = curr_timestamp - start_timestamp
		debug_print("task %u syscall %s pending time %uns" % (common_tid, syscall_name(id), task_state[common_tid]['pending'][id]))
	else:
		delta = curr_timestamp - task_state[common_tid]['sys_enter']
		task_state[common_tid]['count'][id] += 1
		task_state[common_tid]['elapsed'][id] += delta 
		debug_print("delta = %u min = %u max = %u" % (delta, task_state[common_tid]['min'][id], task_state[common_tid]['max'][id]))
		if delta < task_state[common_tid]['min'][id]:
			debug_print("task %u %s min %u" % (common_tid, syscall_name(id), delta))
			task_state[common_tid]['min'][id] = delta
		if delta > task_state[common_tid]['max'][id]:
			debug_print("task %u %s max %u" % (common_tid, syscall_name(id), delta))
			task_state[common_tid]['max'][id] = delta
		debug_print("task %u syscall %s count %u time %uns elapsed %uns" % (common_tid, syscall_name(id), task_state[common_tid]['count'][id], delta, task_state[common_tid]['elapsed'][id]))

	if task_state[common_tid]['cpu'] != common_cpu:
		debug_print("migration within syscall!")
		task_state[common_tid]['migrations'] += 1
		delta /= 2
		debug_print("task %u migrations %u sys %u + %u = %u" % (common_tid, task_state[common_tid]['migrations'], task_state[common_tid]['sys'][task_state[common_tid]['cpu']] - delta, delta, task_state[common_tid]['sys'][task_state[common_tid]['cpu']]))
		task_state[common_tid]['sys'][task_state[common_tid]['cpu']] += delta
		task_state[common_tid]['timestamp'] += delta

	change_mode('user',common_tid,curr_timestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def powerpc__hcall_entry(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, opcode, perf_sample_dict):
	common_tid = common_pid
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s %u [%03u] %s" % (common_secs, common_nsecs, 'hvc_entry', common_tid, common_cpu, hcall_name(opcode)))

	generic_event(event_name, common_cpu, start_timestamp, common_tid, common_comm, 'busy-unknown', getpid, perf_sample_dict)

	task_state[common_tid]['resume-mode'] = task_state[common_tid]['mode']
	task_state[common_tid]['cpu'] = common_cpu
	task_state[common_tid]['opcode'] = opcode
	task_state[common_tid]['hcall_enter'] = curr_timestamp
	if opcode not in task_state[common_tid]['count_hv'].keys():
		new_task_hcall(common_tid, opcode)

	change_mode('hv',common_tid,curr_timestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def powerpc__hcall_exit(event_name, context, common_cpu, common_secs, common_nsecs, common_pid, common_comm, common_callchain, opcode, retval, perf_sample_dict):
	common_tid = common_pid
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s %u [%03u] %u:%s" % (common_secs, common_nsecs, 'hvc_exit', common_tid, common_cpu, opcode, hcall_name(opcode)))

	generic_event(event_name, common_cpu, start_timestamp, common_tid, common_comm, 'busy-unknown', getpid, perf_sample_dict)

	pending = False

	if task_state[common_tid]['mode'] == 'busy-unknown':
		task_state[common_tid]['mode'] = 'hv'
		for cpu in task_state[common_tid]['busy-unknown'].keys():
			task_state[common_tid]['hv'][cpu] = task_state[common_tid]['busy-unknown'][cpu] 
			task_state[common_tid]['busy-unknown'][cpu] = 0
		pending = True

	if opcode not in task_state[common_tid]['count_hv'].keys():
		new_task_hcall(common_tid, opcode)

	if pending:
		task_state[common_tid]['pending_hv'][opcode] = curr_timestamp - start_timestamp
		debug_print("task %u hcall %s pending time %fms" % (common_tid, hcall_name(opcode), task_state[common_tid]['pending_hv'][opcode]))
	else:
		delta = curr_timestamp - task_state[common_tid]['hcall_enter']
		task_state[common_tid]['count_hv'][opcode] += 1
		task_state[common_tid]['elapsed_hv'][opcode] += delta 
		debug_print("delta = %f min = %f max = %f" % (delta, task_state[common_tid]['min_hv'][opcode], task_state[common_tid]['max_hv'][opcode]))
		if delta < task_state[common_tid]['min_hv'][opcode]:
			debug_print("task %u %s min %f" % (common_tid, hcall_name(opcode), delta))
			task_state[common_tid]['min_hv'][opcode] = delta
		if delta > task_state[common_tid]['max_hv'][opcode]:
			debug_print("task %u %s max %f" % (common_tid, hcall_name(opcode), delta))
			task_state[common_tid]['max_hv'][opcode] = delta
		debug_print("task %u hcall %s count %u time %fms elapsed %fms" % (common_tid, hcall_name(opcode), task_state[common_tid]['count_hv'][opcode], delta, task_state[common_tid]['elapsed_hv'][opcode]))

	if task_state[common_tid]['cpu'] != common_cpu:
		debug_print("migration within hcall!")
		task_state[common_tid]['migrations'] += 1
		delta /= 2
		debug_print("task %u migrations %u hv %f + %f = %f" % (common_tid, task_state[common_tid]['migrations'], task_state[common_tid]['hv'][task_state[common_tid]['cpu']] - delta, delta, task_state[common_tid]['hv'][task_state[common_tid]['cpu']]))
		task_state[common_tid]['hv'][task_state[common_tid]['cpu']] += delta
		task_state[common_tid]['timestamp'] += delta

	change_mode(task_state[common_tid]['resume-mode'],common_tid,curr_timestamp)

	if params.debug:
		print_syscall_totals([common_tid])

def sched__sched_switch(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, prev_comm, prev_pid, prev_prio, prev_state, 
	next_comm, next_pid, next_prio, perf_sample_dict):
	common_tid = common_pid
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s %u:%s %u:%s" % (common_secs, common_nsecs, 'switch', prev_pid, task_state[prev_pid]['mode'], next_pid, task_state[next_pid]['mode']))

	generic_event(event_name, common_cpu, start_timestamp, prev_pid, prev_comm, 'busy-unknown', get_unknown, perf_sample_dict)

	if task_state[prev_pid]['sched_stat'] == False:
		task_state[prev_pid]['sched_stat'] = True
		task_state[prev_pid]['runtime'][common_cpu] = curr_timestamp - start_timestamp
		debug_print("%7s.%9s runtime = %u" % ("", "", task_state[prev_pid]['runtime'][common_cpu]))

	task_state[prev_pid]['resume-mode'] = task_state[prev_pid]['mode']
	change_mode('idle', prev_pid, curr_timestamp)

	generic_event(event_name, common_cpu, start_timestamp, next_pid, next_comm, 'idle', get_unknown, perf_sample_dict)

	if task_state[next_pid]['sched_stat'] == False:
		task_state[next_pid]['sched_stat'] = True
		task_state[next_pid]['unaccounted'][common_cpu] = curr_timestamp - start_timestamp
		debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[next_pid]['unaccounted'][common_cpu]))

	task_state[next_pid]['cpu'] = common_cpu

	change_mode(task_state[next_pid]['resume-mode'], next_pid, curr_timestamp)

	if params.debug:
		print_syscall_totals([prev_pid, next_pid])

def sched__sched_migrate_task(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, orig_cpu, 
	dest_cpu, perf_sample_dict):
	common_tid = common_pid
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s pid=%u, orig_cpu=%u, dest_cpu=%u" % (common_secs, common_nsecs, 'migrate', pid, orig_cpu, dest_cpu))

	if orig_cpu == dest_cpu:
		return

	generic_event(event_name, orig_cpu, start_timestamp, pid, comm, 'idle', get_unknown, perf_sample_dict)

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

	debug_print("%07u.%09u %-9s filename=%s, pid=%d, old_pid=%d" % (common_secs, common_nsecs, 'exec', filename, pid, old_pid))

	generic_event(event_name, common_cpu, start_timestamp, old_pid, common_comm, 'sys', get_unknown, perf_sample_dict)

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
		task_state[task]['hv'][cpu] = task_state[old_pid]['hv'][cpu]
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
	for opcode in task_state[old_pid]['count_hv'].keys():
		task_state[task]['count_hv'][opcode] = task_state[old_pid]['count_hv'][opcode]
		task_state[task]['elapsed_hv'][opcode] = task_state[old_pid]['elapsed_hv'][opcode]
		task_state[task]['pending_hv'][opcode] = task_state[old_pid]['pending_hv'][opcode]
		task_state[task]['min_hv'][opcode] = task_state[old_pid]['min_hv'][opcode]
		task_state[task]['max_hv'][opcode] = task_state[old_pid]['max_hv'][opcode]		

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
		print_syscall_totals([old_pid,task])

def sched__sched_process_fork(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, parent_comm, parent_pid, child_comm, child_pid, perf_sample_dict):
	common_tid = common_pid
	common_pid = perf_sample_dict['sample']['pid']
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s [%u:%u] [%u] (parent_pid=%u)" % (common_secs, common_nsecs, 'fork', common_pid, common_tid, child_pid, parent_pid))

	generic_event(event_name, common_cpu, start_timestamp, parent_pid, common_comm, 'sys', getpid, perf_sample_dict)

	generic_event(event_name, common_cpu, curr_timestamp, child_pid, common_comm, 'idle', getpid, perf_sample_dict)

	task_state[child_pid]['sched_stat'] = True
	CLONE = 120
	id = CLONE
	task_state[child_pid]['resume-mode'] = 'sys'
	task_state[child_pid]['id'] = id
	task_state[child_pid]['sys_enter'] = curr_timestamp
	new_task_syscall(child_pid, id)

	if params.debug:
		print_syscall_totals([common_tid, child_pid])

def sched__sched_process_exit(event_name, context, common_cpu,
	common_secs, common_nsecs, common_pid, common_comm,
	common_callchain, comm, pid, prio, perf_sample_dict):
	common_tid = common_pid
	global start_timestamp, curr_timestamp
	curr_timestamp = nsecs(common_secs,common_nsecs)
	if (start_timestamp == 0):
		start_timestamp = curr_timestamp

	debug_print("%07u.%09u %-9s %u" % (common_secs, common_nsecs, 'exit', common_tid))

	generic_event(event_name, common_cpu, start_timestamp, common_tid, common_comm, 'sys', getpid, perf_sample_dict)

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

	generic_event(event_name, common_cpu, start_timestamp, common_pid, common_comm, 'busy-unknown', get_unknown, perf_sample_dict)

	# sched_stat events can occur on any cpu
	# so make sure this doesn't look like a migration
	cpu = task_state[pid]['cpu']

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if runtime > curr_timestamp - start_timestamp:
			runtime = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][cpu] = curr_timestamp - start_timestamp - runtime
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][cpu]))

	debug_print("%7s.%9s runtime %u + %u = %u" % ("", "", task_state[pid]['runtime'][cpu], runtime, task_state[pid]['runtime'][cpu] + runtime))
	task_state[pid]['runtime'][cpu] += runtime

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

	generic_event(event_name, common_cpu, start_timestamp, common_pid, common_comm, 'busy-unknown', get_unknown, perf_sample_dict)

	# sched_stat events can occur on any cpu
	# so make sure this doesn't look like a migration
	cpu = task_state[pid]['cpu']

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][cpu]))

	debug_print("%7s.%9s blocked %u + %u = %u" % ("", "", task_state[pid]['blocked'][cpu], delay, task_state[pid]['blocked'][cpu] + delay))
	task_state[pid]['blocked'][cpu] += delay

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

	generic_event(event_name, common_cpu, start_timestamp, common_pid, common_comm, 'busy-unknown', get_unknown, perf_sample_dict)

	# sched_stat events can occur on any cpu
	# so make sure this doesn't look like a migration
	cpu = task_state[pid]['cpu']

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][cpu]))

	debug_print("%7s.%9s iowait %u + %u = %u" % ("", "", task_state[pid]['iowait'][cpu], delay, task_state[pid]['iowait'][cpu] + delay))
	task_state[pid]['iowait'][cpu] += delay

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

	generic_event(event_name, common_cpu, start_timestamp, common_pid, common_comm, 'busy-unknown', get_unknown, perf_sample_dict)

	# sched_stat events can occur on any cpu
	# so make sure this doesn't look like a migration
	cpu = task_state[pid]['cpu']

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][cpu]))

	debug_print("%7s.%9s wait %u + %u = %u" % ("", "", task_state[pid]['wait'][cpu], delay, task_state[pid]['wait'][cpu] + delay))
	task_state[pid]['wait'][cpu] += delay

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

	generic_event(event_name, common_cpu, start_timestamp, common_pid, common_comm, 'busy-unknown', get_unknown, perf_sample_dict)

	# sched_stat events can occur on any cpu
	# so make sure this doesn't look like a migration
	cpu = task_state[pid]['cpu']

	if task_state[pid]['sched_stat'] == False:
		task_state[pid]['sched_stat'] = True
		if delay > curr_timestamp - start_timestamp:
			delay = curr_timestamp - start_timestamp
		else:
			task_state[pid]['unaccounted'][cpu] = curr_timestamp - start_timestamp - delay
			debug_print("%7s.%9s unaccounted = %u" % ("", "", task_state[pid]['unaccounted'][cpu]))

	debug_print("%7s.%9s sleep %u + %u = %u" % ("", "", task_state[pid]['sleep'][cpu], delay, task_state[pid]['sleep'][cpu] + delay))
	task_state[pid]['sleep'][cpu] += delay

	if params.debug:
		print_syscall_totals([pid])

#def trace_unhandled(event_name, context, event_fields_dict):
#	pass

def print_syscall_totals(tidlist):
	pids = []
	for task in sorted(tidlist):
		pid = task_info[task]['pid']
		if pid not in pids:	
			 pids.append(pid)
	print "--  PID:"
	all_user = 0
	all_sys = 0
	all_hv = 0
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
		print "%7s:" % (str(pid))
		proc_user = 0
		proc_sys = 0
		proc_hv = 0
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
			if task_info[task]['pid'] == pid and task != 0:
				print "     -- [%8s] %-20s %3s %12s %12s %12s %12s %12s | %12s %12s %12s %12s %12s %12s | %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "hv", "busy", "idle", "runtime", "sleep", "wait", "blocked", "iowait", "unaccounted", "util", "moves")
				task_user = 0
				task_sys = 0
				task_hv = 0
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
					print "\t[%8s] %-20s %3u %12.6f %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f" % (task, comm, cpu, ns2ms(task_state[task]['user'][cpu]), ns2ms(task_state[task]['sys'][cpu]), ns2ms(task_state[task]['hv'][cpu]), ns2ms(task_state[task]['busy-unknown'][cpu]), ns2ms(task_state[task]['idle'][cpu]), ns2ms(task_state[task]['runtime'][cpu]), ns2ms(task_state[task]['sleep'][cpu]), ns2ms(task_state[task]['wait'][cpu]), ns2ms(task_state[task]['blocked'][cpu]), ns2ms(task_state[task]['iowait'][cpu]), ns2ms(task_state[task]['unaccounted'][cpu]))
					task_user += task_state[task]['user'][cpu]
					task_sys += task_state[task]['sys'][cpu]
					task_hv += task_state[task]['hv'][cpu]
					task_idle += task_state[task]['idle'][cpu]
					task_busy += task_state[task]['busy-unknown'][cpu]
					task_running = task_user + task_sys + task_hv + task_busy
					task_runtime += task_state[task]['runtime'][cpu]
					task_sleep += task_state[task]['sleep'][cpu]
					task_wait += task_state[task]['wait'][cpu]
					task_blocked += task_state[task]['blocked'][cpu]
					task_iowait += task_state[task]['iowait'][cpu]
					task_unaccounted += task_state[task]['unaccounted'][cpu]
				print "\t[%8s] %-20s ALL %12.6f %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f | %5.1f%% %6u" % (task, comm, ns2ms(task_user), ns2ms(task_sys), ns2ms(task_hv), ns2ms(task_busy), ns2ms(task_idle), ns2ms(task_runtime), ns2ms(task_sleep), ns2ms(task_wait), ns2ms(task_blocked), ns2ms(task_iowait), ns2ms(task_unaccounted), (task_running * 100 / (task_running + task_idle)) if task_running > 0 else 0, task_migrations)
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
							new_task_syscall('ALL', id)
						task_state['ALL']['count'][id] += count
						task_state['ALL']['elapsed'][id] += elapsed
						task_state['ALL']['pending'][id] += pending
						if min < task_state['ALL']['min'][id]:
							task_state['ALL']['min'][id] = min
						if max > task_state['ALL']['max'][id]:
							task_state['ALL']['max'][id] = max
					print
				if task_state[task]['count_hv']:
					print "\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("hvc", "name", "count", "elapsed", "pending", "average", "minimum", "maximum")
					for opcode in sorted(task_state[task]['count_hv'].keys(), key= lambda x: (task_state[task]['count_hv'][x], task_state[task]['elapsed_hv'][x]), reverse=True):
						count_hv = task_state[task]['count_hv'][opcode]
						elapsed_hv = task_state[task]['elapsed_hv'][opcode]
						pending_hv = task_state[task]['pending_hv'][opcode]
						min_hv = task_state[task]['min_hv'][opcode]
						max_hv = task_state[task]['max_hv'][opcode]
						print "\t\t(%3u)%-20s %6u %12.6f %12.6f" % (opcode, hcall_name(opcode), count_hv, ns2ms(elapsed_hv), ns2ms(pending_hv)),
						if count_hv > 0:
							print " %12.6f %12.6f %12.6f" % (ns2ms(elapsed_hv)/count_hv, ns2ms(min_hv), ns2ms(max_hv))
						else:
							print " %12s %12s %12s" % ("--", "--", "--")
						if opcode not in task_state['ALL']['count_hv'].keys():
							new_task_hcall('ALL', opcode)
						task_state['ALL']['count_hv'][opcode] += count_hv
						task_state['ALL']['elapsed_hv'][opcode] += elapsed_hv
						task_state['ALL']['pending_hv'][opcode] += pending_hv
						if min_hv < task_state['ALL']['min_hv'][opcode]:
							task_state['ALL']['min_hv'][opcode] = min_hv
						if max_hv > task_state['ALL']['max_hv'][opcode]:
							task_state['ALL']['max_hv'][opcode] = max_hv
					print					
				proc_user += task_user
				proc_sys += task_sys
				proc_hv += task_hv
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
		all_hv += proc_hv
		all_idle += proc_idle
		all_busy += proc_busy
		all_runtime += proc_runtime
		all_sleep += proc_sleep
		all_wait += proc_wait
		all_blocked += proc_blocked
		all_iowait += proc_iowait
		all_unaccounted += proc_unaccounted
		all_migrations += proc_migrations
		print "     -- [%8s] %-20s %3s %12s %12s %12s %12s %12s | %12s %12s %12s %12s %12s %12s | %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "hv", "busy", "idle", "runtime", "sleep", "wait", "blocked", "iowait", "unaccounted", "util", "moves")
		print "\t[     ALL] %-20s ALL %12.6f %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f | %5.1f%% %6u" % ("", ns2ms(proc_user), ns2ms(proc_sys), ns2ms(proc_hv), ns2ms(proc_busy), ns2ms(proc_idle), ns2ms(proc_runtime), ns2ms(proc_sleep), ns2ms(proc_wait), ns2ms(proc_blocked), ns2ms(proc_iowait), ns2ms(proc_unaccounted), ((proc_user + proc_sys + + proc_hv + proc_busy) * 100 / (proc_user + proc_sys + proc_hv + proc_busy + proc_idle)) if proc_user + proc_sys + proc_hv + proc_busy > 0 else 0, proc_migrations)

	print

	print "%7s:" % ("ALL")
	print "     -- [%8s] %-20s %3s %12s %12s %12s %12s %12s | %12s %12s %12s %12s %12s %12s | %5s%% %6s" % ("task", "command", "cpu", "user", "sys", "hv", "busy", "idle", "runtime", "sleep", "wait", "blocked", "iowait", "unaccounted", "util", "moves")
        # is it correct to add in hv here?
	print "\t[     ALL] %-20s ALL %12.6f %12.6f %12.6f %12.6f %12.6f | %12.6f %12.6f %12.6f %12.6f %12.6f %12.6f | %5.1f%% %6u" % ("", ns2ms(all_user), ns2ms(all_sys), ns2ms(all_hv), ns2ms(all_busy), ns2ms(all_idle), ns2ms(all_runtime), ns2ms(all_sleep), ns2ms(all_wait), ns2ms(all_blocked), ns2ms(all_iowait), ns2ms(all_unaccounted), ((all_user + all_sys + all_hv + all_busy) * 100 / (all_user + all_sys + all_hv + all_busy + all_idle)) if all_user + all_sys + all_hv + all_busy > 0 else 0, all_migrations)
	print
	if task_state['ALL']['count']:
		print "\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("id", "name", "count", "elapsed", "pending", "average", "minimum", "maximum")
		for id in sorted(task_state['ALL']['count'].keys(), key= lambda x: (task_state['ALL']['count'][x], task_state['ALL']['elapsed'][x]), reverse=True):
			print "\t\t(%3u)%-20s %6u %12.6f %12.6f" % (id, syscall_name(id), task_state['ALL']['count'][id], ns2ms(task_state['ALL']['elapsed'][id]), ns2ms(task_state['ALL']['pending'][id])),
			if task_state['ALL']['count'][id] > 0:
				print " %12.6f %12.6f %12.6f" % (ns2ms(task_state['ALL']['elapsed'][id]/task_state['ALL']['count'][id]), ns2ms(task_state['ALL']['min'][id]), ns2ms(task_state['ALL']['max'][id]))
			else:
				print " %12s %12s %12s" % ("--", "--", "--")
		print

	if task_state['ALL']['count_hv']:
		print "\t     -- (%3s)%-20s %6s %12s %12s %12s %12s %12s" % ("hvc", "name", "count", "elapsed", "pending", "average", "minimum", "maximum")
		for opcode in sorted(task_state['ALL']['count_hv'].keys(), key= lambda x: (task_state['ALL']['count_hv'][x], task_state['ALL']['elapsed_hv'][x]), reverse=True):
			print "\t\t(%3u)%-20s %6u %12.6f %12.6f" % (opcode, hcall_name(opcode), task_state['ALL']['count_hv'][opcode], ns2ms(task_state['ALL']['elapsed_hv'][opcode]), ns2ms(task_state['ALL']['pending_hv'][opcode])),
			if task_state['ALL']['count_hv'][opcode] > 0:
				print " %12.6f %12.6f %12.6f" % (ns2ms(task_state['ALL']['elapsed_hv'][opcode]/task_state['ALL']['count_hv'][opcode]), ns2ms(task_state['ALL']['min_hv'][opcode]), ns2ms(task_state['ALL']['max_hv'][opcode]))
			else:
				print " %12s %12s %12s" % ("--", "--", "--")
		print

	del task_state['ALL']
	print "Total Trace Time: %f ms" % ns2ms(curr_timestamp - start_timestamp)

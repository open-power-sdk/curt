# Project Description
This project calculates utilization statistics:
1. What percentage of time is each process/task running, divided into "user" and "system" time
1. Idle time is broken down into sleep, wait, blocked, and I/O wait
1. System time is further divided among syscalls, with an invocation count, elapsed time, running (system) time, idle time, minimum, maximum, and average call duration
1. Task migrations
1. Hypervisor calls are tracked per task, per process, and system wide, with invocation count, elapsed time, running (system) time, minimum, maximum, and average call duration

Usage is a two-step process (described in more detail below):
1. Collect trace data using `perf`
1. Process collected data using `perf` with this project's Python script

## Contributing to the project
We welcome contributions to the curt project in many forms. There's always plenty to do! Full details of how to contribute to this project are documented in the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## Maintainers
The project's [maintainers](MAINTAINERS.txt) are responsible for reviewing and merging all pull requests and they guide the over-all technical direction of the project.

## Communication <a name="communication"></a>
We use [SDK Tools for Power Slack](https://toolsforpower.slack.com/) for communication.

## Installing
Currently, the only project file used in processing is `curt.py`.  One could download that directly from the [curt GitHub repository](https://github.ibm.com/sdk/curt), or clone the git repository and use it from there:
```
    $ git clone https://github.ibm.com/sdk/curt.git
    $ ls curt/curt.py
    curt/curt.py
```

## Documentation

### Set up

1. If you wish to run perf as a non-root user, you'll need superuser authority to set some things up:

   1. Make sure you have read/write access to `/sys/kernel/debug/tracing`:
      ```
      /usr/bin/sudo /usr/bin/mount -o remount,mode=755 /sys/kernel/debug
      ```

   1. Enable any user to be able to collect system-wide events:
      ```
      echo -1 | /usr/bin/sudo /usr/bin/tee /proc/sys/kernel/perf_event_paranoid
      ```

   1. Install Linux audit's python bindings:
      ```
      /usr/bin/sudo /usr/bin/yum install audit-libs-python
      ```
      or
      ```
      /usr/bin/sudo apt-get install python-audit
      ```

### Collect trace data

1. Simple!
```
    perf record -e '{raw_syscalls:*,sched:sched_switch,sched:sched_migrate_task,sched:sched_process_exec,sched:sched_process_fork,sched:sched_process_exit,sched:sched_stat_runtime,sched:sched_stat_wait,sched:sched_stat_sleep,sched:sched_stat_blocked,sched:sched_stat_iowait,powerpc:hcall_entry,powerpc:hcall_exit}' -a *command --args*
```

If some statistics are not needed, not all events need be traced.  This can be helpful to reduce the trace file size.  The following are subsets of the trace events, and the statistics for which those events are required:

| events | statistics |
| --- | --- |
| `sched:sched_switch`, `sched:sched_process_exec`, `sched:sched_process_fork`, `sched:sched_process_exit` | per-task user, system, hypervisor, idle time |
| `sched:sched_migrate_task` | accurate migrations and per-cpu statistics |
| `sched:sched_stat_runtime`, `sched:sched_stat_wait`, `sched:sched_stat_sleep`, `sched:sched_stat_blocked`, `sched:sched_stat_iowait` | per-task idle-time classification |
| `raw_syscalls:sys_enter`, `raw_syscalls:sys_exit` | system call statistics |
| `powerpc:hcall_entry`, `powerpc:hcall_exit` | hypervisor call statistics (POWER architecture only) |

### Process trace data

1. Simple!
```
    perf script -s ./curt.py
```

Or, even simpler, `curt.py` can be used directly (it will execute `perf` itself):
```
    ./curt.py
```

Like `perf`, `curt.py` will operate on `perf.data` by default.  To operate on a different file:
```
    ./curt.py my-trace-file.data
```

### Help

The full command help can be displayed:
```
    ./curt.py --help
```

### A note on `perf` versions

As of this writing, there are two versions of the Python APIs for `perf`:
1. An older API, which is currently found in all major Linux distributions
2. A newer API, which is found in newer kernels

The most significant difference between the two APIs, with respect to `curt`, is that the older API does not provide sufficient information to determine the process IDs for tasks.

`curt` is able to use either API by using the `--api` command option.  `--api=1` selects the older API, and is the default API selection (so `--api=1` is not required).  `--api=2` selects the newer API.

When using the older API, all tasks will be grouped under an `unknown` process ID.  One may use the older API on any kernel.

When using the new API on newer kernels, tasks will be grouped under their respective process IDs.

When attempting to use the new API on older kernels, `curt` will fail with an error like the following:
```
    TypeError: powerpc__hcall_entry_new() takes exactly 10 arguments (9 given)
```

### A note on `perf` trace data

`curt.py` keeps track of task states as it parses the `perf` data file.  This naturally depends on the events in the file being ordered in time.  Unfortunately, `perf` does not guarantee that the events in a trace file are in time order.  `curt.py` attempts to process the events in any trace file in time order by looking ahead and reordering if needed.  To keep the process of looking ahead from taking too much memory, it is limited in the number of events.  By default, this limit is 20 events.  This limit can be changed by using the `--window` option with `curt.py`.

Regardless of success for `curt.py` looking ahead, the `perf` command will still report that it detected out-of-order events:
```
Warning:
2 out of order events recorded.
```
These warnings can be ignored.

If, however, the look-ahead window for `curt.py` is too small, `curt.py` will report an error:
```
Error: OUT OF ORDER events detected.
  Try increasing the size of the look-ahead window with --window=<n>
```
As suggested, increasing the look-ahead window size sufficiently will address this issue.

## Still Have Questions?
For general purpose questions, please use [StackOverflow](http://stackoverflow.com/questions/tagged/toolsforpower).

## License <a name="license"></a>
The [curt](https://github.ibm.com/sdk/curt) project uses the [GPL License Version 2.0](LICENSE) software license.

## Related information
The [curt](https://github.ibm.com/sdk/curt) project is inspired by the [AIX curt tool](https://www.ibm.com/support/knowledgecenter/en/ssw_aix_72/com.ibm.aix.prftools/idprftools_cpu.htm)

# Project Description
This project calculates utilization statistics:
1. What percentage of time is each process/task running, divided into "user" and "system" time
2. System time is further divided among syscalls, with an invocation count, elapsed time, running (system) time, idle time, minimum, maximum, and average call duration
3. Task migrations

The current implementation is based on collecting trace data using "perf", and post-processing the data using perf's python scripting capabilities.

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
1. Get a recent version of "perf", as full "ppc64le" support arrived in Linux kernel 4.14.
   * fix to perf's `Util.py` file for `ppc64le`
   * Ubuntu still needs perf's python scripting enabled
   * Building your own version of perf:
     * clone kernel source...
     * install pre-requisites...
     * build perf...
     * install perf...

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
    perf record -e '{raw_syscalls:*,sched:sched_switch,sched:sched_migrate_task,sched:sched_process_exec,sched:sched_process_fork,sched:sched_process_exit}' --exclude-perf -a *command --args*
```

### Process trace data
1. Simple!
```
    perf script -s ./curt.py
```

## Still Have Questions?
For general purpose questions, please use [StackOverflow](http://stackoverflow.com/questions/tagged/toolsforpower).

## License <a name="license"></a>
The [curt](https://github.ibm.com/sdk/curt) project uses the [GPL License Version 2.0](LICENSE) software license.

## Related information
The [curt](https://github.ibm.com/sdk/curt) project is inspired by the [AIX curt tool](https://www.ibm.com/support/knowledgecenter/en/ssw_aix_72/com.ibm.aix.prftools/idprftools_cpu.htm)

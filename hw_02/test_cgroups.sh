#!/bin/sh

set -uo pipefail

if [ $(id -u) -ne 0 ]; then
	echo 'Please, run this script as root'
	echo 'It needs permissions for operations with cgroups'
	exit 1
fi

function noop() {
	printf "\n"
}

trap noop SIGINT

msg='Send a SIGINT signal to continue... (e.g. press CTRL-C)'

# Case in the root cgroup.
read -p "Starting stress in root cgroup. Press Enter to continue..."
echo "$msg"
stress --cpu 4 --vm 1 --vm-bytes 2147483648 --vm-hang 10

cgroup_name='test_cgroups_hw_2'
read -p "Enter cgroup $cgroup_name, limit memory to 512m, start stress. Press Enter to continue..."

# Create custom cgroup for testing
cd /sys/fs/cgroup
if [ ! -d "$cgroup_name" ]; then
	mkdir "$cgroup_name"
fi
cd "$cgroup_name"

# Limit memory
echo 512m > memory.high
echo 512m > memory.max

# Move this shell process into the custom testing cgroup
echo $$ > cgroup.procs

echo "$msg"
stress --cpu 4 --vm 1 --vm-bytes 2147483648 --vm-hang 10

read -p "Set CPU quota to 50 ms over the period of 100 ms, start stress. Press Enter to continue..."

# set cpu quota to 50000 us over the period of 100000 us
# = 50 ms over the period of 100 ms
# Quota is distributed over all the processes in the group
echo 50000 > cpu.max

echo "$msg"
stress --cpu 4 --vm 1 --vm-bytes 2147483648 --vm-hang 10

read -p "Limit memory to 5m, start stress. Press Enter to continue..."

# Limit memory even more, will trigger OOM killer
echo 5m > memory.swap.high
echo 5m > memory.swap.max

echo "Now stress will get oom killed"

echo "$msg"
stress --cpu 4 --vm 1 --vm-bytes 2147483648 --vm-hang 10

# Make sure the stress process finishes
sleep 1

# Move this shell process to the root cgroup
cd ..
echo $$ > cgroup.procs

# remove testing cgroup
rmdir "$cgroup_name"

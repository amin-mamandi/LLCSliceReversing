numactl --membind=4 sudo ./oneslice_attacker \
  --slices 10 \
  --target-slice 3 \
  -m 4096 \
  -a read \
  -n 1 \
  -c 2 \
  --base 0x1c \
  --event 0xf50 \
  -f 3 \
  -k 100 \
  --use-embedded-hash

numactl --membind=4 sudo ./oneslice_attacker \
  --slices 10 \
  --target-slice 3 \
  -m 4096 \
  -a read \
  -n 1 \
  -c 2 \
  --base 0x1c \
  --event 0xf50 \
  -f 3 \
  -k 100 \
  --use-embedded-hash \
  --verify-hash \
  --print-confusion \
  --auto-tune-hash \
  --tune-top 3

sudo perf stat -a \
  $(for i in $(seq 0 39); do
      printf " -e uncore_cha_%d/event=0x50,umask=0x0f/" "$i"
    done) \
  -- sleep 1


# 0) Load msr module once
sudo modprobe msr

# 1) Verify current prefetch-control value on all CPUs
sudo rdmsr -a 0x1a4 | sort | uniq -c

# 2) Save backup (safe revert point)
for c in /dev/cpu/[0-9]*; do
  cpu=${c##*/}
  val=$(sudo rdmsr -p "$cpu" 0x1a4)
  printf "%s 0x%s\n" "$cpu" "$val"
done > prefetch_1a4_backup.txt

# 3) Disable prefetchers using only writable bits on your platform
#    (bit6 is blocked on your machine, so use 0x2f)
sudo wrmsr -a 0x1a4 0x2f

# 4) Verify disable took effect
sudo rdmsr -a 0x1a4 | sort | uniq -c
# expect all CPUs at 2f

# 5) Revert to baseline (your known good value)
sudo wrmsr -a 0x1a4 0x20

# 6) Verify revert
sudo rdmsr -a 0x1a4 | sort | uniq -c
# expect all CPUs at 20
# Windows Performance Baselines & Counter Thresholds

## Category: Performance Counter Specifications
**Source:** Microsoft Windows Performance & Scalability Team  
**Tags:** baseline, counters, thresholds, cpu, memory, disk, network

---

### Section: CPU Utilization Baselines
- **Processor: % Processor Time:**
  - Normal: < 70% average.
  - Warning: 70% - 85% sustained for > 5 minutes.
  - Critical: > 85% sustained for > 2 minutes.
- **System: Processor Queue Length:**
  - Normal: < 2 per core.
  - Warning: 2 - 4 per core.
  - Critical: > 5 per core (threads waiting for execution).
- **Processor: % Privileged Time:**
  - Normal: < 30% of total CPU time.
  - Warning: > 35% indicates high kernel driver activity, I/O handling, or DPC/interrupt storms.

---

### Section: Memory Performance Baselines
- **Memory: Available MBytes:**
  - Normal: > 20% of installed physical RAM.
  - Warning: < 1000 MB.
  - Critical: < 500 MB (acute memory starvation, triggering working set trimming).
- **Paging File: % Usage:**
  - Normal: < 30%.
  - Warning: 50% - 70%.
  - Critical: > 75% (imminent pagefile expansion or out-of-memory crashes).
- **Memory: Pages/sec:**
  - Normal: < 20 pages/sec.
  - Warning: 20 - 100 pages/sec.
  - Critical: > 100 pages/sec (active disk-memory thrashing).

---

### Section: Disk Storage Baselines
- **PhysicalDisk: % Disk Time:**
  - Normal: < 50%.
  - Warning: 70% - 85%.
  - Critical: > 90% (disk head thrashing, saturated IOPS).
- **PhysicalDisk: Avg. Disk Queue Length:**
  - Normal: < 2.0 per physical spindle.
  - Critical: > 4.0 sustained.
- **PhysicalDisk: Avg. Disk sec/Transfer (Latency):**
  - Normal: < 10 ms (SSDs) or < 15 ms (HDDs).
  - Warning: 15 ms - 25 ms.
  - Critical: > 25 ms.

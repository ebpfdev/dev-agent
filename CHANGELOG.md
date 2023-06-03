v0.0.2 // 3 july 2023 / export to Prometheus metrics
--

* (feature) eBPF metrics prometheus exporter:
  * progs statistics (run_time, run_count)
  * maps statistics
    * number of entries (if configured, see [README](./README.md)
    * value of entries (if configured)
* Bugfixes:
  * removing trailing zeros from byte array, when converting map's keys/values to string
  * fixed converting map's key/value to number, when it's less than 8 bytes

v0.0.1 // 28 june 2023 / GraphQL kickstarted
--

* GraphQL API, which exposes:
    * programs and maps metadata
    * traversing between programs and maps

      relation is defined by `bpf_prog_aux->used_maps` ([see in Linux](https://github.com/torvalds/linux/blob/4ecd704a4c51fd95973fcc3a60444e0e24eb9439/include/linux/bpf.h#L1400))
    * map entries including various representation (hex, number, string)
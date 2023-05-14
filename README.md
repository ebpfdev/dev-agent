# dev-agent
This agent provides access to system's eBPF-programs and maps to perform remote debugging.

# Usage

## GraphQL server

```shell
sudo ./phydev server
```

GraphQL interface: [http://localhost:8080/](http://localhost:8080/)
Schema: [pkg/graph/schema.graphqls](pkg/graph/schema.graphqls)

![GraphQL interface example](docs/graphql-example.png)



## CLI commands

List loaded eBPF programs:

```shell
sudo ./phydev inspect progs list
> ID      Type    Tag     RunCount        RunTime AvgRunTime
> 3               CGroupDevice    e3dbd137be8d6168        0       0s      0s
> 4               CGroupSKB       6deef7357e7b4530        0       0s      0s
> 125     uprobe__BIO_new Kprobe  0d9ea14e5516f975        0       0s      0s
> 126     socket__http_fi SocketFilter    6b7ab673cb23d3f0        0       0s      0s
> 127     kretprobe__do_s Kprobe  154f35d6575c73f9        0       0s      0s
> 128     uretprobe__SSL_ Kprobe  8737d2e349595de3        0       0s      0s
```

List loaded eBPF maps:

```shell
% sudo ./phydev inspect maps list 
ID      Name    FD      Type    Flags   IsPinned        KeySize ValueSize       MaxEntries
1               3       Hash    0       false   9       1       500
2               4       Hash    0       false   9       1       500
44      do_sendfile_arg 10      Hash    0       false   8       8       1024
61      http_in_flight  27      Hash    0       false   48      112     10000
62      http_notificati 28      PerfEventArray  0       false   4       4       16
63      open_at_args    29      Hash    0       false   8       128     1024
```

# Development

## Build
```shell
go build -o phydev cmd/dev-agent/main.go
```

## Update GraphQL models from schema

To update GraphQL models, run:
```shell
go generate ./...
```

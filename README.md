# zzzxx

zzzxx is a lightweight tool that leverages eBPF to trace syscall events.

## Installation

### Prerequisites
- Go 1.23+
- [`ig`](https://www.inspektor-gadget.io/docs/latest/reference/install-linux) 0.37+

### Clone the repository
```sh
git clone https://github.com/dorser/zzzxxx.git
cd zzzxxx
```

### Build
To build the project for all supported architectures, run:
```sh
make
```
To build for a specific architecture:
```sh
make amd64  # or make arm64
```

To build the containerized gadget:
```sh
make build-gadget-trace_exec
```

### Cleaning Up
To remove generated binaries and build artifacts:
```sh
make clean
```

## Usage
Once built, you can run the tool to trace syscall events (Must be run as root):
```sh
sudo ./dist/zzzxx-linux-amd64  # for x86_64
sudo ./dist/zzzxx-linux-arm64  # for arm64
```


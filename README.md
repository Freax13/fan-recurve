# fan-recurve

A tool to modify the fan curves on the BMCs of Supermicro motherboards. It modifies the fan curves directly in memory of the `ipmi_sensor` process.

fan-recurve has been tested on firmware version 01.01.06. It will likely not work with other versions.

## Warning

Use this tool at your own risk! Messing with the BMC's memory is a delicate process and it's very possible that this tool will mess up. If you experience any problems, reset the BMC.

## Building

I recommend using [cross](https://github.com/cross-rs/cross):
```bash
cross build --target arm-unknown-linux-gnueabi --release
```
The binary will be under `target/arm-unknown-linux-gnueabi/release/fan-recurve`.

## Usage

You will need to execute this tool directly on the BMC. AFAICT there is no official method to do this.

1. Dump the current fan curves:
```bash
# Dump all fan curves.
fan_recurve dump

# Filter by zone.
fan_recurve dump --zone 0
fan_recurve dump --zone 0 --zone 2

# Filter by sensor name.
fan_recurve dump --sensor HDD
fan_recurve dump --sensor HDD --sensor '^SSD'

# Filter by fan mode.
fan_recurve dump --fan-mode optimal
fan_recurve dump --fan-mode optimal --fan-mode smart

# Write the fan curves to a file.
fan_recurve dump -f /tmp/dump.yaml
```

2. Open up the dump and modify the curves.

The `tn_offset` and `pn_offset` values shouldn't be modified, they just contain the offset of the pn and tn tables in memory. The values under `info` are purely informational and don't get written back when patching.

3. Patch the curves.

```bash
fan_recurve patch --file /tmp/patched.yaml
```

This will patch the fan curves directly in memory of the `ipmi_sensor` process. The patch is not persistent and will not survive reboots. If you experience any problems with the patched values, simply reset the BMC.

## Other

There's a neat trick to tricking the BMC into tolerating fans that spin down to 0 RPM:
```bash
ipmitool sensor thresh FAN1 lower 17920 17920 17920
```
Setting the lower threshold to 17920 will trick the BMC into thinking that the threshold is actually negative. This works because it divides the thresholds by 140 internally and interprets the result as a two's complement 8-bit signed integer.
```
17920 / 140 = 128 = 0x80
0x80 is -128 is two's complement.
```

Redfish will complain that the fan's health status is critical, but the BMC won't peg the other fans to 100% or send a health alert.
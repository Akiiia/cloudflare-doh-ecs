import { concatBytes, readU16, writeU16, writeU32 } from "./binary";
import { DnsFormatError, type DnsMessageInfo } from "./dns";
import type { EcsSubnet } from "./ip";

const ECS_OPTION_CODE = 8;
const DEFAULT_UDP_PAYLOAD_SIZE = 1232;

function encodeEcsOption(subnet: EcsSubnet): Uint8Array {
  const addressLength = Math.ceil(subnet.prefixLength / 8);
  const optionDataLength = 4 + addressLength;
  const output = new Uint8Array(4 + optionDataLength);
  writeU16(output, 0, ECS_OPTION_CODE);
  writeU16(output, 2, optionDataLength);
  writeU16(output, 4, subnet.family);
  output[6] = subnet.prefixLength;
  output[7] = 0;
  output.set(subnet.network.subarray(0, addressLength), 8);
  return output;
}

function filteredOptions(
  message: Uint8Array,
  info: DnsMessageInfo,
  subnet: EcsSubnet | null
): Uint8Array {
  const opt = info.opt;
  if (opt === null) return new Uint8Array();
  const parts: Uint8Array[] = [];
  let offset = opt.rdataStart;
  while (offset < opt.rdataEnd) {
    if (offset + 4 > opt.rdataEnd) {
      throw new DnsFormatError("truncated_edns_option");
    }
    const code = readU16(message, offset);
    const length = readU16(message, offset + 2);
    const end = offset + 4 + length;
    if (end > opt.rdataEnd) {
      throw new DnsFormatError("truncated_edns_option_data");
    }
    if (code !== ECS_OPTION_CODE) {
      parts.push(message.slice(offset, end));
    }
    offset = end;
  }
  if (subnet !== null) parts.push(encodeEcsOption(subnet));
  return concatBytes(parts);
}

export function rewriteEcs(
  message: Uint8Array,
  info: DnsMessageInfo,
  subnet: EcsSubnet | null
): Uint8Array {
  if (info.opt === null) {
    if (subnet === null) return message;
    const ecs = encodeEcsOption(subnet);
    const opt = new Uint8Array(11 + ecs.length);
    opt[0] = 0;
    writeU16(opt, 1, 41);
    writeU16(opt, 3, DEFAULT_UDP_PAYLOAD_SIZE);
    writeU32(opt, 5, 0);
    writeU16(opt, 9, ecs.length);
    opt.set(ecs, 11);

    const output = concatBytes([message, opt]);
    writeU16(output, 10, info.additionalCount + 1);
    return output;
  }

  if (info.optAdditionalIndex !== info.additionalCount - 1) {
    throw new DnsFormatError("opt_must_be_last_additional");
  }

  const options = filteredOptions(message, info, subnet);
  const prefix = message.slice(0, info.opt.rdataStart);
  const output = concatBytes([prefix, options]);
  writeU16(output, info.opt.rdataStart - 2, options.length);
  return output;
}

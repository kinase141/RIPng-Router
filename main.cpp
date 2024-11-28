#include "checksum.h"
#include "common.h"
#include "eui64.h"
#include "lookup.h"
#include "protocol.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <map>
#include <algorithm>
#include <functional>
using namespace std;

uint8_t packet[2048];
uint8_t output[2048];

#ifdef ROUTER_R1
// 0: fd00::1:1/112
// 1: fd00::3:1/112
// 2: fd00::6:1/112
// 3: fd00::7:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x01, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x06, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x07, 0x00, 0x01},
};
#elif defined(ROUTER_R2)
// 0: fd00::3:2/112
// 1: fd00::4:1/112
// 2: fd00::8:1/112
// 3: fd00::9:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x04, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x08, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x09, 0x00, 0x01},
};
#elif defined(ROUTER_R3)
// 0: fd00::4:2/112
// 1: fd00::5:2/112
// 2: fd00::a:1/112
// 3: fd00::b:1/112
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x04, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x05, 0x00, 0x02},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x0a, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x0b, 0x00, 0x01},
};
#else

// 0: fd00::0:1
// 1: fd00::1:1
// 2: fd00::2:1
// 3: fd00::3:1
in6_addr addrs[N_IFACE_ON_BOARD] = {
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x01, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x02, 0x00, 0x01},
    {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x03, 0x00, 0x01},
};
#endif

class Table
{
public:
  in6_addr addr; // IPv6 address
  uint32_t len;  // Length of the prefix (subnet mask length)

  Table(in6_addr addr, uint32_t len) : addr(addr), len(len) {}

  // Overloading the '<' operator for ordering in the map
  bool operator<(const Table &other) const
  {
    // Comparison logic based on address and length
    if (memcmp(&addr, &other.addr, sizeof(in6_addr)) != 0)
    {
      return memcmp(&addr, &other.addr, sizeof(in6_addr)) < 0;
    }
    return len < other.len;
  }
};
extern map<Table, RoutingTableEntry> RoutingTable;
void printRoutingTable()
{
  for (const auto &entry : RoutingTable)
  {
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(entry.first.addr), ip_str, INET6_ADDRSTRLEN);
    printf("Route to %s/%d, via interface %d, metric %d\n",
           ip_str, entry.first.len, entry.second.if_index, entry.second.metric);
  }
}

void setupIPHeader(uint8_t *output, in6_addr ip_src, in6_addr ip_dst, int headerLength, int entriesLength)
{
  ip6_hdr *ip6 = (ip6_hdr *)output;
  ip6->ip6_flow = 0;
  ip6->ip6_vfc = 6 << 4;
  ip6->ip6_nxt = IPPROTO_UDP;
  ip6->ip6_hlim = 255;
  ip6->ip6_src = ip_src;
  ip6->ip6_dst = ip_dst;

  ip6->ip6_plen = htons(headerLength + entriesLength);
}

void setupUDPHeader(uint8_t *output)
{
  udphdr *udp = (udphdr *)(output + sizeof(ip6_hdr));
  udp->uh_dport = htons(521);
  udp->uh_sport = htons(521);
  udp->uh_ulen = ((ip6_hdr *)output)->ip6_plen;
}

void sendPacket(int if_index, in6_addr ip_src, in6_addr ip_dst, ether_addr mac_dst, RipngPacket &rip, int entriesCount)
{
  rip.numEntries = entriesCount;
  int totalHeaderLength = sizeof(udphdr) + sizeof(ripng_hdr);
  int totalEntriesLength = sizeof(ripng_rte) * entriesCount;

  setupIPHeader(output, ip_src, ip_dst, totalHeaderLength, totalEntriesLength);
  setupUDPHeader(output);

  uint8_t *payload = output + 48;
  assemble(&rip, payload);

  validateAndFillChecksum(output, totalHeaderLength + totalEntriesLength + sizeof(ip6_hdr));
  HAL_SendIPPacket(if_index, output, totalHeaderLength + totalEntriesLength + sizeof(ip6_hdr), mac_dst);
}

in6_addr iptmp = {};

int main(int argc, char *argv[])
{
  int res = HAL_Init(1, addrs);
  if (res < 0)
  {
    return res;
  }
  iptmp.s6_addr[0] = 0xff;
  iptmp.s6_addr[1] = 0x02;
  iptmp.s6_addr[15] = 0x09;

  // fd00::3:0/112 if 0
  // fd00::4:0/112 if 1
  // fd00::8:0/112 if 2
  // fd00::9:0/112 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    in6_addr mask = len_to_mask(112);
    RoutingTableEntry entry = {
        .addr = addrs[i] & mask,
        .len = 112,
        .if_index = i,
        .nexthop = in6_addr{0}, 
        .route_tag = 0,
        .metric = 1};

    update(true, entry);
  }

#ifdef ROUTER_INTERCONNECT
  RoutingTableEntry entry = {
      .addr = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x01, 0x00, 0x00},
      .len = 112,
      .if_index = 0,
      .nexthop = {0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x03, 0x00, 0x01}};
  update(true, entry);
#endif

  uint64_t last_time = 0;
  while (1)
  {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000)
    {
      int i = 0;
      while (i < N_IFACE_ON_BOARD)
      {
        ether_addr mac;
        HAL_GetInterfaceMacAddress(i, &mac);
        in6_addr ip_src = eui64(mac);

        ether_addr mac_dst;
        const unsigned char new_values[] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x09};
        std::copy(new_values, new_values + 6, mac_dst.ether_addr_octet);

        RipngPacket rip;
        bool hasEntries = false;
        const int MAX_ENTRIES = 25;
        int entryCount = 0;

        auto iter = RoutingTable.begin();

        if (hasEntries)
        {
        }
        while (iter != RoutingTable.end())
        {
          hasEntries = true;

          rip.command = 2;
          rip.entries[entryCount].prefix_or_nh = iter->second.addr;
          rip.entries[entryCount].route_tag = iter->second.route_tag;
          rip.entries[entryCount].metric = (i == iter->second.if_index) ? 16 : iter->second.metric;
          rip.entries[entryCount].prefix_len = iter->second.len;

          if (++entryCount == MAX_ENTRIES)
          {
            sendPacket(i, ip_src, iptmp, mac_dst, rip, MAX_ENTRIES);
            entryCount = 0;
            hasEntries = false;
          }

          ++iter;
          if (hasEntries)
          {
          }
        }

        if (hasEntries)
        {
          sendPacket(i, ip_src, iptmp, mac_dst, rip, entryCount);
        }

        i++;
      }

      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    ether_addr src_mac;
    ether_addr dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), &src_mac, &dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF)
    {
      break;
    }
    else if (res < 0)
    {
      return res;
    }
    else if (res == 0)
    {
      // Timeout
      continue;
    }
    else if (res > sizeof(packet))
    {
      // packet is truncated, ignore it
      continue;
    }

    ip6_hdr *ip6 = (ip6_hdr *)packet;
    if (res < sizeof(ip6_hdr))
    {
      // printf("Received invalid ipv6 packet (%d < %d)\n", res, sizeof(ip6_hdr));
      continue;
    }
    uint16_t plen = ntohs(ip6->ip6_plen);
    if (res < plen + sizeof(ip6_hdr))
    {
      // printf("Received invalid ipv6 packet (%d < %d + %d)\n", res, plen,
      continue;
    }

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++)
    {
      if (memcmp(&ip6->ip6_dst, &addrs[i], sizeof(in6_addr)) == 0)
      {
        dst_is_me = true;
        break;
      }
    }


    if (ip6->ip6_dst == iptmp)
    {
      dst_is_me = true;
    }

    if (dst_is_me)
    {

      if (ip6->ip6_nxt == IPPROTO_UDP || ip6->ip6_nxt == IPPROTO_ICMPV6)
      {
        if (!validateAndFillChecksum(packet, res))
        {
          // printf("Received packet with bad checksum\n");
          continue;
        }
      }

      if (ip6->ip6_nxt == IPPROTO_UDP)
      {
        RipngPacket ripng;
        RipngErrorCode err = disassemble(packet, res, &ripng);
        if (err == SUCCESS)
        {
          if (ripng.command == 1)
          {

            RipngPacket resp;

            ether_addr mac;
            HAL_GetInterfaceMacAddress(if_index, &mac);
            in6_addr ip_src = eui64(mac);
            in6_addr ip_dst = ip6->ip6_src;
            ether_addr mac_dst = src_mac;
            RipngPacket rip;
            bool hasEntries = false;
            const int MAX_ENTRIES = 25;
            int entryCount = 0;

            auto iter = RoutingTable.begin();

            if (hasEntries)
            {
            }
            while (iter != RoutingTable.end())
            {
              hasEntries = true;

              rip.command = 2;
              rip.entries[entryCount].prefix_or_nh = iter->second.addr;
              rip.entries[entryCount].route_tag = iter->second.route_tag;
              rip.entries[entryCount].metric = (if_index == iter->second.if_index) ? 16 : iter->second.metric;
              rip.entries[entryCount].prefix_len = iter->second.len;

              if (++entryCount == MAX_ENTRIES)
              {
                sendPacket(if_index, ip_src, ip_dst, mac_dst, rip, MAX_ENTRIES);
                entryCount = 0;
                hasEntries = false;
              }

              ++iter;
              if (hasEntries)
              {
              }
            }

            if (hasEntries)
            {
              sendPacket(if_index, ip_src, ip_dst, mac_dst, rip, entryCount);
            }
          }
          else
          {
            int i = 0;
            while (i < ripng.numEntries)
            {
              auto &entry = ripng.entries[i];

              if (entry.metric == 0xff)
              {
                i++;
                continue;
              }

              uint8_t metric = entry.metric + 1;
              metric = (metric > 15) ? 16 : metric;

              auto table = Table(entry.prefix_or_nh, entry.prefix_len);
              auto duplicate = RoutingTable.find(table);

              if (duplicate == RoutingTable.end())
              {
                if (metric < 16)
                {
                  RoutingTableEntry newEntry = {
                      entry.prefix_or_nh,
                      entry.prefix_len,
                      uint32_t(if_index),
                      ip6->ip6_src,
                      entry.route_tag,
                      metric};
                  update(true, newEntry);
                }
                i++;
                continue;
              }

              if (duplicate->second.nexthop == ip6->ip6_src)
              {
                duplicate->second.metric = metric;
                duplicate->second.if_index = if_index;
                duplicate->second.nexthop = ip6->ip6_src;
                RoutingTable[table] = duplicate->second;
              }
              else if (metric < duplicate->second.metric)
              {
                RoutingTableEntry newEntry = {
                    entry.prefix_or_nh,
                    entry.prefix_len,
                    if_index,
                    ip6->ip6_src,
                    entry.route_tag,
                    metric};
                RoutingTable[table] = newEntry;
              }

              i++;
            }
          }
        }
        else
        {
        }
      }
      else if (ip6->ip6_nxt == IPPROTO_ICMPV6)
      {

        if (false)
        {
        }
        auto *ip_header = reinterpret_cast<ip6_hdr *>(packet);
        auto *icmp_header = reinterpret_cast<icmp6_hdr *>(packet + sizeof(ip6_hdr));

        if (icmp_header->icmp6_type == ICMP6_ECHO_REQUEST)
        {
          std::copy(packet, packet + res, output);
          auto *reply_ip_header = reinterpret_cast<ip6_hdr *>(output);
          auto *reply_icmp_header = reinterpret_cast<icmp6_hdr *>(output + sizeof(ip6_hdr));
          reply_ip_header->ip6_src = ip6->ip6_dst;
          reply_ip_header->ip6_dst = ip6->ip6_src;
          reply_ip_header->ip6_hlim = 64;
          reply_icmp_header->icmp6_type = ICMP6_ECHO_REPLY;
          validateAndFillChecksum(output, res);
          HAL_SendIPPacket(if_index, output, res, src_mac);
        }
      }
      continue;
    }
    else
    {
      if (ip6->ip6_dst.s6_addr[0] == 0xff)
      {
        // printf("Don't forward multicast packet to %s\n",
        //        inet6_ntoa(ip6->ip6_dst));
        continue;
      }

      uint8_t ttl = ip6->ip6_hops;
      if (ttl <= 1)
      {
        int packet_len;
        if (res > 1232)
        {
          packet_len = 1232;
        }
        else
        {
          packet_len = res;
        }

        ip6_hdr *ip_header = (ip6_hdr *)output;
        icmp6_hdr *icmp_header = (icmp6_hdr *)(output + sizeof(ip6_hdr));
        ip_header->ip6_flow = 0;
        ip_header->ip6_vfc = 0x60;
        ip_header->ip6_plen = ntohs(packet_len + sizeof(icmp6_hdr));
        ip_header->ip6_nxt = 58;
        ip_header->ip6_hlim = 255;
        icmp_header->icmp6_type = 3;
        icmp_header->icmp6_code = 0;
        ip_header->ip6_src = addrs[if_index];
        ip_header->ip6_dst = ip6->ip6_src;
        icmp_header->icmp6_cksum = 0;
        unsigned char *packet_data_dest = output + sizeof(ip6_hdr) + sizeof(icmp6_hdr);
        for (int i = 0; i < packet_len; i++)
        {
          packet_data_dest[i] = ((unsigned char *)packet)[i];
        }
        size_t total_length = sizeof(ip6_hdr) + sizeof(icmp6_hdr) + packet_len;
        validateAndFillChecksum(output, total_length);
        HAL_SendIPPacket(if_index, output, total_length, src_mac);
      }
      else
      {
        in6_addr nexthop;
        uint32_t dest_if;
        if (prefix_query(ip6->ip6_dst, &nexthop, &dest_if))
        {
          ether_addr dest_mac;
          if (nexthop == in6_addr{0})
          {
            nexthop = ip6->ip6_dst;
          }
          if (HAL_GetNeighborMacAddress(dest_if, nexthop, &dest_mac) == 0)
          {
            ip6->ip6_hops--;

            memcpy(output, packet, res);
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
          else
          {
            // printf("Nexthop ip %s is not found in NDP table\n",
            //        inet6_ntoa(nexthop));
          }
        }
        else
        {
          int packet_len = std::min(res, 1232);

          ip6_hdr *ip_header = reinterpret_cast<ip6_hdr *>(output);
          icmp6_hdr *icmp_header = reinterpret_cast<icmp6_hdr *>(output + sizeof(ip6_hdr));

          ip_header->ip6_flow = 0; // flow label
          ip_header->ip6_vfc = 0x60;
          ip_header->ip6_plen = htons(static_cast<uint16_t>(sizeof(icmp6_hdr) + packet_len));
          ip_header->ip6_nxt = IPPROTO_ICMPV6;
          ip_header->ip6_hlim = 255;
          ip_header->ip6_src = addrs[if_index];
          ip_header->ip6_dst = ip6->ip6_src;

          icmp_header->icmp6_type = 1; // ICMPv6 Destination Unreachable
          icmp_header->icmp6_code = 0; // No route to destination
          icmp_header->icmp6_cksum = 0;
          unsigned char *dest = output + sizeof(ip6_hdr) + sizeof(icmp6_hdr);
          const unsigned char *src = static_cast<const unsigned char *>(packet);
          for (int i = 0; i < packet_len; ++i)
          {
            dest[i] = src[i];
          }
          validateAndFillChecksum(output, sizeof(ip6_hdr) + sizeof(icmp6_hdr) + packet_len);
          HAL_SendIPPacket(if_index, output, sizeof(ip6_hdr) + sizeof(icmp6_hdr) + packet_len, src_mac);

        }
      }
    }
  }
  return 0;
}
